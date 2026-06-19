use std::cmp;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use blake2::{
    Blake2bVar,
    digest::{KeyInit as Blake2KeyInit, Mac, Update, VariableOutput, consts::U32},
};
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit as Poly1305KeyInit, OsRng, Payload, rand_core::RngCore},
};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::diag;
use crate::error::VaultError;
use crate::types::{BlobId, ChunkEntry, FileCompleteEntry, FileId, VaultId, VaultMasterKey};

const FRONT_MATTER_LEN: u64 = 4096;
const SALT_LEN: usize = 32;
const STABLE_SLOT_OFFSET: u64 = 32;
const STABLE_SLOT_LEN: usize = 2016;
const VOLATILE_A_OFFSET: u64 = 2048;
const VOLATILE_B_OFFSET: u64 = 3072;
const VOLATILE_SLOT_LEN: usize = 1024;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const STABLE_PLAINTEXT_LEN: usize = STABLE_SLOT_LEN - NONCE_LEN - TAG_LEN;
const VOLATILE_PLAINTEXT_LEN: usize = VOLATILE_SLOT_LEN - NONCE_LEN - TAG_LEN;
const STABLE_PAYLOAD_LEN: usize = 152;
const WRAPPED_KEY_LEN: usize = 48;
const STABLE_VAULT_ID_OFFSET: usize = 0;
const STABLE_BLOB_ID_OFFSET: usize = 16;
const STABLE_WRAPPED_K_DATA_OFFSET: usize = 32;
const STABLE_WRAPPED_K_INDEX_OFFSET: usize = 80;
const STABLE_INDEX_NONCE_OFFSET: usize = 128;
const VOLATILE_PAYLOAD_LEN: usize = 56;
const CHUNK_OVERHEAD: u64 = (NONCE_LEN + TAG_LEN) as u64;
const CHUNK_ENTRY_PAYLOAD_LEN: usize = 72;
const CHUNK_ENTRY_WIRE_LEN: usize = CHUNK_ENTRY_PAYLOAD_LEN + 1;
const FILE_COMPLETE_PAYLOAD_LEN: usize = 56;
const FILE_COMPLETE_ENTRY_WIRE_LEN: usize = FILE_COMPLETE_PAYLOAD_LEN + 1;
/// Bytes of index plaintext per chunk entry (`0x01` tag + payload).
pub const INDEX_CHUNK_ENTRY_BYTES: u64 = CHUNK_ENTRY_WIRE_LEN as u64;
/// Bytes of index plaintext per `file_complete` entry.
pub const INDEX_FILE_COMPLETE_ENTRY_BYTES: u64 = FILE_COMPLETE_ENTRY_WIRE_LEN as u64;
/// AEAD frame overhead per chunk (24-byte nonce + 16-byte tag).
pub const AEAD_FRAME_OVERHEAD: u64 = CHUNK_OVERHEAD;
const MAX_CHUNK_PLAINTEXT_LEN: u64 = (1_u64 << 38) - 64;

/// Writer and reader policy for values the spec leaves to the application.
#[derive(Clone, Debug)]
pub struct BlobConfig {
    /// Random bytes between the data tail and the first index in a new blob.
    pub initial_leading_gap: u64,
    /// Random bytes after the index in a new blob.
    pub initial_trailing_gap: u64,
    /// Minimum leading gap after Case 2 relocation (`new_index_offset - data_tail`).
    pub relocation_leading_padding: u64,
    /// Random bytes written after the index on Case 2 relocation.
    pub relocation_trailing_padding: u64,
    /// Reader retries after index MAC failure (concurrent writer / relocation).
    pub reader_retry_budget: usize,
    /// Emit stderr diagnostics (also enabled when `VAULTBLOB_DEBUG` is set).
    pub diagnostics: bool,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            initial_leading_gap: 1024 * 1024,
            initial_trailing_gap: 1024 * 1024,
            relocation_leading_padding: 8 * 1024 * 1024,
            relocation_trailing_padding: 1024 * 1024,
            reader_retry_budget: 3,
            diagnostics: false,
        }
    }
}

/// One chunk to append in a transaction.
#[derive(Clone, Debug)]
pub struct NewChunk {
    pub file_id: FileId,
    pub sequence_number: u64,
    pub plaintext: Vec<u8>,
}

/// Optional file completion marker to append with a transaction.
#[derive(Clone, Debug)]
pub struct NewFileComplete {
    pub file_id: FileId,
    pub total_chunks: u64,
    pub full_content_hash: [u8; 32],
}

/// Decoded canonical index contents.
#[derive(Clone, Debug, Default)]
pub struct BlobIndex {
    pub chunks: Vec<ChunkEntry>,
    pub completed_files: Vec<FileCompleteEntry>,
}

/// Result of a successful chunk append transaction.
#[derive(Clone, Debug)]
pub struct WriteChunksResult {
    pub entries: Vec<ChunkEntry>,
    pub index: BlobIndex,
}

/// Physical layout breakdown for one blob file (debugging / capacity planning).
#[derive(Clone, Debug, Default)]
pub struct BlobLayoutStats {
    pub file_size: u64,
    pub front_matter_bytes: u64,
    pub body_bytes: u64,
    pub locator_generation: u64,
    pub chunk_count: usize,
    pub file_complete_count: usize,
    pub chunk_plaintext_bytes: u64,
    pub chunk_frame_bytes: u64,
    pub chunk_frame_overhead_bytes: u64,
    pub gap_before_first_chunk_bytes: u64,
    pub inter_chunk_gap_bytes: u64,
    pub data_tail: u64,
    pub leading_gap_bytes: u64,
    pub index_offset: u64,
    pub index_length: u64,
    pub index_ciphertext_bytes: u64,
    pub index_entry_plaintext_bytes: u64,
    pub trailing_gap_bytes: u64,
    pub body_unclassified_bytes: u64,
}

struct CommittedSnapshot {
    locator: Locator,
    index: BlobIndex,
    index_plaintext: Vec<u8>,
}

pub struct Blob {
    pub path: PathBuf,
    pub vault_id: VaultId,
    pub blob_id: BlobId,
    file: File,
    k_data: [u8; 32],
    k_index: [u8; 32],
    k_mac: [u8; 32],
    index_nonce: [u8; NONCE_LEN],
    config: BlobConfig,
    committed: Option<CommittedSnapshot>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Locator {
    generation: u64,
    index_offset: u64,
    index_length: u64,
    index_mac: [u8; 32],
    slot_index: u8,
}

struct PreparedChunk {
    entry: ChunkEntry,
    frame: Vec<u8>,
}

struct WritePlan {
    chunks: Vec<PreparedChunk>,
    index_entries: Vec<u8>,
    total_chunk_len: u64,
}

impl CommittedSnapshot {
    fn locator_matches(&self, locator: &Locator) -> bool {
        self.locator == *locator
    }
}

struct ExclusiveLock(libc::c_int);

impl Blob {
    pub fn open<P: AsRef<Path>>(
        path: P,
        vault_id: VaultId,
        master_key: &VaultMasterKey,
        config: BlobConfig,
    ) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        let existed = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        if existed && file.metadata()?.len() >= FRONT_MATTER_LEN {
            Self::from_existing(path, file, vault_id, master_key, config)
        } else {
            Self::create_new(path, &mut file, vault_id, master_key, config)
        }
    }

    pub fn open_existing<P: AsRef<Path>>(
        path: P,
        vault_id: VaultId,
        master_key: &VaultMasterKey,
        config: BlobConfig,
    ) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        Self::from_existing(path, file, vault_id, master_key, config)
    }

    pub fn layout_stats(&mut self) -> Result<BlobLayoutStats, VaultError> {
        let locator = self.read_active_locator()?;
        let (index, index_plaintext) = self.read_index_with_locator(&locator)?;
        let file_size = self.file.metadata()?.len();

        let mut chunk_plaintext_bytes = 0_u64;
        let mut chunk_frame_bytes = 0_u64;
        for entry in &index.chunks {
            chunk_plaintext_bytes = checked_add(chunk_plaintext_bytes, entry.plaintext_length)?;
            chunk_frame_bytes = checked_add(
                chunk_frame_bytes,
                checked_add(entry.plaintext_length, AEAD_FRAME_OVERHEAD)?,
            )?;
        }

        let mut sorted_chunks = index.chunks.clone();
        sorted_chunks.sort_by_key(|entry| entry.offset_in_blob);

        let gap_before_first_chunk_bytes = sorted_chunks
            .first()
            .map(|entry| entry.offset_in_blob.saturating_sub(FRONT_MATTER_LEN))
            .unwrap_or(0);

        let mut inter_chunk_gap_bytes = 0_u64;
        let mut cursor = FRONT_MATTER_LEN;
        for entry in &sorted_chunks {
            if entry.offset_in_blob > cursor {
                inter_chunk_gap_bytes =
                    checked_add(inter_chunk_gap_bytes, entry.offset_in_blob - cursor)?;
            }
            cursor = checked_add(
                entry.offset_in_blob,
                checked_add(entry.plaintext_length, AEAD_FRAME_OVERHEAD)?,
            )?;
        }

        let data_tail = self.data_tail(&index)?;
        let index_end = checked_add(locator.index_offset, locator.index_length)?;
        let leading_gap_bytes = locator.index_offset.saturating_sub(data_tail);
        let trailing_gap_bytes = file_size.saturating_sub(index_end);

        let classified = checked_add(
            chunk_frame_bytes,
            checked_add(
                gap_before_first_chunk_bytes,
                checked_add(
                    inter_chunk_gap_bytes,
                    checked_add(
                        leading_gap_bytes,
                        checked_add(locator.index_length, trailing_gap_bytes)?,
                    )?,
                )?,
            )?,
        )?;
        let body_bytes = file_size.saturating_sub(FRONT_MATTER_LEN);
        let body_unclassified_bytes = body_bytes.saturating_sub(classified);

        Ok(BlobLayoutStats {
            file_size,
            front_matter_bytes: FRONT_MATTER_LEN,
            body_bytes,
            locator_generation: locator.generation,
            chunk_count: index.chunks.len(),
            file_complete_count: index.completed_files.len(),
            chunk_plaintext_bytes,
            chunk_frame_bytes,
            chunk_frame_overhead_bytes: chunk_frame_bytes.saturating_sub(chunk_plaintext_bytes),
            gap_before_first_chunk_bytes,
            inter_chunk_gap_bytes,
            data_tail,
            leading_gap_bytes,
            index_offset: locator.index_offset,
            index_length: locator.index_length,
            index_ciphertext_bytes: locator.index_length,
            index_entry_plaintext_bytes: index_plaintext.len() as u64,
            trailing_gap_bytes,
            body_unclassified_bytes,
        })
    }

    pub fn read_index(&mut self) -> Result<BlobIndex, VaultError> {
        let attempts = self.config.reader_retry_budget + 1;
        self.log_diag(format!(
            "read_index: starting (retry_budget={}, attempts={attempts})",
            self.config.reader_retry_budget
        ));

        for attempt in 0..attempts {
            let locators = self.read_sorted_locators()?;
            let locator = locators[0].clone();
            let walk_start = std::time::Instant::now();
            match self.read_index_with_locator(&locator) {
                Ok((index, _)) => {
                    self.log_diag(format!(
                        "read_index: attempt {attempt} ok in {:?} via slot {} (chunks={}, completed_files={})",
                        diag::elapsed(walk_start),
                        locator.slot_index,
                        index.chunks.len(),
                        index.completed_files.len()
                    ));
                    return Ok(index);
                }
                Err(VaultError::IndexMacMismatch) => {
                    self.log_diag(format!(
                        "read_index: attempt {attempt} slot {} MAC mismatch in {:?} ({})",
                        locator.slot_index,
                        diag::elapsed(walk_start),
                        diag::format_locator(
                            locator.slot_index,
                            locator.generation,
                            locator.index_offset,
                            locator.index_length,
                        )
                    ));
                }
                Err(VaultError::IndexChainBroken) => {
                    self.log_diag(format!(
                        "read_index: attempt {attempt} slot {} index corrupt in {:?}",
                        locator.slot_index,
                        diag::elapsed(walk_start),
                    ));
                    return Err(VaultError::IndexChainBroken);
                }
                Err(err) => {
                    self.log_diag(format!(
                        "read_index: attempt {attempt} fatal {:?}: {}",
                        diag::elapsed(walk_start),
                        diag::format_vault_error(&err)
                    ));
                    return Err(err);
                }
            }
        }

        self.log_diag("read_index: RetryBudgetExceeded");
        Err(VaultError::RetryBudgetExceeded)
    }

    pub fn read_chunk(&mut self, entry: &ChunkEntry) -> Result<Vec<u8>, VaultError> {
        let frame_len = checked_add(entry.plaintext_length, CHUNK_OVERHEAD)?;
        let frame = self.read_at(entry.offset_in_blob, frame_len)?;
        self.decrypt_chunk(entry, &frame)
    }

    pub fn read_chunk_by_id(
        &mut self,
        file_id: FileId,
        sequence_number: u64,
    ) -> Result<Vec<u8>, VaultError> {
        let index = self.read_index()?;
        let entry = index
            .chunks
            .iter()
            .find(|entry| entry.file_id == file_id && entry.sequence_number == sequence_number)
            .ok_or(VaultError::IndexChainBroken)?;
        self.read_chunk(entry)
    }

    pub fn write_chunks(
        &mut self,
        chunks: &[NewChunk],
        completed_files: &[NewFileComplete],
    ) -> Result<WriteChunksResult, VaultError> {
        let _lock = ExclusiveLock::acquire(&self.file)?;
        self.log_diag("write_chunks: acquired exclusive lock");

        let locator = self.read_active_locator()?;
        let (mut index, mut index_plaintext) = self.load_index_for_write(&locator)?;
        let data_tail = self.data_tail(&index)?;

        let plan = self.prepare_write(chunks, completed_files, data_tail)?;
        let entry_len = plan.index_entries.len() as u64;
        let chunk_len = plan.total_chunk_len;

        let index_offset = locator.index_offset;
        let index_length = locator.index_length;
        let index_end = checked_add(index_offset, index_length)?;
        let leading_gap = index_offset.saturating_sub(data_tail);
        let eof = self.file.metadata()?.len();
        let trailing_gap = eof
            .checked_sub(index_end)
            .ok_or(VaultError::IndexChainBroken)?;

        let needs_relocate = chunk_len > leading_gap || entry_len > trailing_gap;

        let (new_index_offset, new_index_length, new_generation) = if needs_relocate {
            self.log_diag(format!(
                "write_chunks: Case 2 relocate (leading_gap={leading_gap}, need_chunks={chunk_len}; \
                 trailing_gap={trailing_gap}, need_index_entries={entry_len})"
            ));
            self.relocate_and_append_index(&locator, &plan, data_tail, &index_plaintext)?
        } else {
            self.log_diag("write_chunks: Case 1 append");
            let mut offset = data_tail;
            for chunk in &plan.chunks {
                self.write_all_at(offset, &chunk.frame)?;
                offset = checked_add(offset, chunk.frame.len() as u64)?;
            }
            self.file.sync_all()?;

            let entry_ciphertext = index_stream_xor(
                &self.k_index,
                &self.index_nonce,
                index_length,
                &plan.index_entries,
            )?;
            self.write_all_at(index_end, &entry_ciphertext)?;
            self.file.sync_all()?;

            (
                index_offset,
                checked_add(index_length, entry_len)?,
                locator.generation + 1,
            )
        };

        let new_ciphertext = self.read_at(new_index_offset, new_index_length)?;
        let new_mac = compute_index_mac(
            &self.k_mac,
            &self.vault_id,
            &self.blob_id,
            new_generation,
            new_index_length,
            &new_ciphertext,
        )?;

        let new_locator = Locator {
            generation: new_generation,
            index_offset: new_index_offset,
            index_length: new_index_length,
            index_mac: new_mac,
            slot_index: 1 - locator.slot_index,
        };
        self.write_volatile_slot(&new_locator)?;
        self.file.sync_all()?;

        index_plaintext.extend_from_slice(&plan.index_entries);
        for chunk in &plan.chunks {
            index.chunks.push(chunk.entry.clone());
        }
        for complete in completed_files {
            index.completed_files.push(FileCompleteEntry {
                file_id: complete.file_id,
                total_chunks: complete.total_chunks,
                full_content_hash: complete.full_content_hash,
            });
        }

        self.committed = Some(CommittedSnapshot {
            locator: new_locator,
            index: index.clone(),
            index_plaintext,
        });

        let entries = plan.chunks.into_iter().map(|c| c.entry).collect();
        Ok(WriteChunksResult { entries, index })
    }

    pub fn refresh_committed_snapshot(&mut self) -> Result<BlobIndex, VaultError> {
        let locators = self.read_sorted_locators()?;
        for locator in locators {
            match self.read_index_with_locator(&locator) {
                Ok((index, index_plaintext)) => {
                    self.committed = Some(CommittedSnapshot {
                        locator,
                        index: index.clone(),
                        index_plaintext,
                    });
                    return Ok(index);
                }
                Err(VaultError::IndexMacMismatch | VaultError::IndexChainBroken) => continue,
                Err(err) => return Err(err),
            }
        }
        Err(VaultError::RetryBudgetExceeded)
    }

    fn from_existing(
        path: PathBuf,
        mut file: File,
        expected_vault_id: VaultId,
        master_key: &VaultMasterKey,
        config: BlobConfig,
    ) -> Result<Self, VaultError> {
        validate_config(&config)?;
        let mut stable_slot = [0_u8; STABLE_SLOT_LEN];
        file.seek(SeekFrom::Start(STABLE_SLOT_OFFSET))?;
        file.read_exact(&mut stable_slot)?;

        let stable = decrypt_slot(&master_key.0, &stable_slot, &expected_vault_id.0)?;
        if stable.len() < STABLE_PAYLOAD_LEN {
            return Err(VaultError::AeadDecryptFailed);
        }

        let vault_id = VaultId(copy_array(
            &stable[STABLE_VAULT_ID_OFFSET..STABLE_VAULT_ID_OFFSET + 16],
        ));
        if vault_id != expected_vault_id {
            return Err(VaultError::InvalidMasterKey);
        }
        let blob_id = BlobId(copy_array(
            &stable[STABLE_BLOB_ID_OFFSET..STABLE_BLOB_ID_OFFSET + 16],
        ));
        let wrapped_k_data = copy_array::<WRAPPED_KEY_LEN>(
            &stable[STABLE_WRAPPED_K_DATA_OFFSET..STABLE_WRAPPED_K_DATA_OFFSET + WRAPPED_KEY_LEN],
        );
        let wrapped_k_index = copy_array::<WRAPPED_KEY_LEN>(
            &stable[STABLE_WRAPPED_K_INDEX_OFFSET..STABLE_WRAPPED_K_INDEX_OFFSET + WRAPPED_KEY_LEN],
        );
        let k_data = unwrap_stable_key(&master_key.0, &vault_id, "K_data", &wrapped_k_data)?;
        let k_index = unwrap_stable_key(&master_key.0, &vault_id, "K_index", &wrapped_k_index)?;
        let mut index_nonce = [0_u8; NONCE_LEN];
        index_nonce.copy_from_slice(
            &stable[STABLE_INDEX_NONCE_OFFSET..STABLE_INDEX_NONCE_OFFSET + NONCE_LEN],
        );

        let k_mac = derive_index_mac_key(&k_index, &blob_id);

        Ok(Self {
            path,
            file,
            vault_id,
            blob_id,
            k_data,
            k_index,
            k_mac,
            index_nonce,
            config,
            committed: None,
        })
    }

    fn create_new(
        path: PathBuf,
        file: &mut File,
        vault_id: VaultId,
        master_key: &VaultMasterKey,
        config: BlobConfig,
    ) -> Result<Self, VaultError> {
        validate_config(&config)?;
        let _lock = ExclusiveLock::acquire(file)?;

        let mut salt = [0_u8; SALT_LEN];
        let mut blob_id = [0_u8; 16];
        let mut k_data = [0_u8; 32];
        let mut k_index = [0_u8; 32];
        let mut index_nonce = [0_u8; NONCE_LEN];
        fill_random(&mut salt);
        fill_random(&mut blob_id);
        fill_random(&mut k_data);
        fill_random(&mut k_index);
        fill_random(&mut index_nonce);

        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&salt)?;

        let wrapped_k_data = wrap_stable_key(&master_key.0, &vault_id, "K_data", &k_data)?;
        let wrapped_k_index = wrap_stable_key(&master_key.0, &vault_id, "K_index", &k_index)?;

        let mut stable_plaintext = vec![0_u8; STABLE_PLAINTEXT_LEN];
        stable_plaintext[STABLE_VAULT_ID_OFFSET..STABLE_VAULT_ID_OFFSET + 16]
            .copy_from_slice(&vault_id.0);
        stable_plaintext[STABLE_BLOB_ID_OFFSET..STABLE_BLOB_ID_OFFSET + 16]
            .copy_from_slice(&blob_id);
        stable_plaintext
            [STABLE_WRAPPED_K_DATA_OFFSET..STABLE_WRAPPED_K_DATA_OFFSET + WRAPPED_KEY_LEN]
            .copy_from_slice(&wrapped_k_data);
        stable_plaintext
            [STABLE_WRAPPED_K_INDEX_OFFSET..STABLE_WRAPPED_K_INDEX_OFFSET + WRAPPED_KEY_LEN]
            .copy_from_slice(&wrapped_k_index);
        stable_plaintext[STABLE_INDEX_NONCE_OFFSET..STABLE_INDEX_NONCE_OFFSET + NONCE_LEN]
            .copy_from_slice(&index_nonce);
        fill_random(&mut stable_plaintext[STABLE_PAYLOAD_LEN..]);

        let stable_slot = encrypt_slot(&master_key.0, &stable_plaintext, &vault_id.0)?;
        file.write_all(&stable_slot)?;

        let blob_id = BlobId(blob_id);
        let k_mac = derive_index_mac_key(&k_index, &blob_id);

        let index_offset = checked_add(FRONT_MATTER_LEN, config.initial_leading_gap)?;
        let index_length = 0_u64;
        let index_mac = compute_index_mac(&k_mac, &vault_id, &blob_id, 0, index_length, &[])?;

        let locator = Locator {
            generation: 0,
            index_offset,
            index_length,
            index_mac,
            slot_index: 0,
        };

        let mut blob = Self {
            path,
            file: file.try_clone()?,
            vault_id,
            blob_id,
            k_data,
            k_index,
            k_mac,
            index_nonce,
            config,
            committed: None,
        };

        let volatile = blob.make_volatile_slot(&locator)?;
        blob.file.seek(SeekFrom::Start(VOLATILE_A_OFFSET))?;
        blob.file.write_all(&volatile)?;

        let mut inactive = [0_u8; VOLATILE_SLOT_LEN];
        fill_random(&mut inactive);
        blob.file.seek(SeekFrom::Start(VOLATILE_B_OFFSET))?;
        blob.file.write_all(&inactive)?;

        let body_len = checked_add(
            blob.config.initial_leading_gap,
            blob.config.initial_trailing_gap,
        )?;
        blob.write_random_at(FRONT_MATTER_LEN, body_len)?;
        blob.file.sync_all()?;

        blob.committed = Some(CommittedSnapshot {
            locator,
            index: BlobIndex::default(),
            index_plaintext: Vec::new(),
        });

        Ok(blob)
    }

    fn load_index_for_write(
        &mut self,
        locator: &Locator,
    ) -> Result<(BlobIndex, Vec<u8>), VaultError> {
        if let Some(committed) = &self.committed {
            if committed.locator_matches(locator) {
                self.log_diag(
                    "write_chunks: volatile locator matches committed snapshot; skipping index read",
                );
                return Ok((committed.index.clone(), committed.index_plaintext.clone()));
            }
        }
        self.read_index_with_locator(locator)
    }

    fn read_index_with_locator(
        &mut self,
        locator: &Locator,
    ) -> Result<(BlobIndex, Vec<u8>), VaultError> {
        let ciphertext = if locator.index_length == 0 {
            Vec::new()
        } else {
            self.read_at(locator.index_offset, locator.index_length)?
        };

        let expected_mac = compute_index_mac(
            &self.k_mac,
            &self.vault_id,
            &self.blob_id,
            locator.generation,
            locator.index_length,
            &ciphertext,
        )?;
        if !constant_time_eq32(&expected_mac, &locator.index_mac) {
            self.log_diag("read_index: IndexMacMismatch");
            return Err(VaultError::IndexMacMismatch);
        }

        let mut plaintext = ciphertext;
        index_stream_decrypt_in_place(&self.k_index, &self.index_nonce, &mut plaintext)?;

        let mut index = BlobIndex::default();
        parse_entries(&plaintext, &mut index)?;
        Ok((index, plaintext))
    }

    fn relocate_and_append_index(
        &mut self,
        locator: &Locator,
        plan: &WritePlan,
        data_tail: u64,
        existing_plaintext: &[u8],
    ) -> Result<(u64, u64, u64), VaultError> {
        let entry_len = plan.index_entries.len() as u64;
        let chunk_len = plan.total_chunk_len;
        let index_length = locator.index_length;

        let new_index_offset = checked_add(
            data_tail,
            checked_add(chunk_len, self.config.relocation_leading_padding)?,
        )?;
        let new_index_length = checked_add(index_length, entry_len)?;
        let required_eof = checked_add(
            new_index_offset,
            checked_add(new_index_length, self.config.relocation_trailing_padding)?,
        )?;
        let eof = self.file.metadata()?.len();
        if required_eof > eof {
            self.write_random_at(eof, required_eof - eof)?;
        }

        if index_length > 0 {
            let existing = self.read_at(locator.index_offset, index_length)?;
            self.write_all_at(new_index_offset, &existing)?;
        }

        let entry_ciphertext = index_stream_xor(
            &self.k_index,
            &self.index_nonce,
            index_length,
            &plan.index_entries,
        )?;
        self.write_all_at(
            checked_add(new_index_offset, index_length)?,
            &entry_ciphertext,
        )?;

        let mut offset = data_tail;
        for chunk in &plan.chunks {
            self.write_all_at(offset, &chunk.frame)?;
            offset = checked_add(offset, chunk.frame.len() as u64)?;
        }
        self.file.sync_all()?;

        debug_assert_eq!(existing_plaintext.len() as u64, index_length);
        Ok((new_index_offset, new_index_length, locator.generation + 1))
    }

    fn read_sorted_locators(&mut self) -> Result<Vec<Locator>, VaultError> {
        let a = self.read_volatile_slot(0)?;
        let b = self.read_volatile_slot(1)?;

        if self.diagnostics_enabled() {
            match &a {
                Some(loc) => self.log_diag(format!(
                    "volatile slot A: {}",
                    diag::format_locator(
                        loc.slot_index,
                        loc.generation,
                        loc.index_offset,
                        loc.index_length,
                    )
                )),
                None => self.log_diag("volatile slot A: invalid or empty"),
            }
            match &b {
                Some(loc) => self.log_diag(format!(
                    "volatile slot B: {}",
                    diag::format_locator(
                        loc.slot_index,
                        loc.generation,
                        loc.index_offset,
                        loc.index_length,
                    )
                )),
                None => self.log_diag("volatile slot B: invalid or empty"),
            }
        }

        let mut locators = Vec::new();
        if let Some(a) = a {
            locators.push(a);
        }
        if let Some(b) = b {
            locators.push(b);
        }
        if locators.is_empty() {
            return Err(VaultError::NoValidLocator);
        }
        locators.sort_by(|left, right| right.generation.cmp(&left.generation));
        Ok(locators)
    }

    fn read_active_locator(&mut self) -> Result<Locator, VaultError> {
        let locators = self.read_sorted_locators()?;
        let chosen = locators[0];
        self.log_diag(format!(
            "read_active_locator: chose {}",
            diag::format_locator(
                chosen.slot_index,
                chosen.generation,
                chosen.index_offset,
                chosen.index_length,
            )
        ));
        Ok(chosen)
    }

    fn read_volatile_slot(&mut self, slot_index: u8) -> Result<Option<Locator>, VaultError> {
        let offset = if slot_index == 0 {
            VOLATILE_A_OFFSET
        } else {
            VOLATILE_B_OFFSET
        };
        let mut slot = [0_u8; VOLATILE_SLOT_LEN];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut slot)?;

        let aad = volatile_aad(self.vault_id, self.blob_id, slot_index);
        let Ok(plaintext) = decrypt_slot(&self.k_index, &slot, &aad) else {
            return Ok(None);
        };
        if plaintext.len() < VOLATILE_PAYLOAD_LEN {
            return Ok(None);
        }

        Ok(Some(Locator {
            generation: read_u64(&plaintext[0..8]),
            index_offset: read_u64(&plaintext[8..16]),
            index_length: read_u64(&plaintext[16..24]),
            index_mac: copy_array(&plaintext[24..56]),
            slot_index,
        }))
    }

    fn make_volatile_slot(&self, locator: &Locator) -> Result<Vec<u8>, VaultError> {
        let mut plaintext = vec![0_u8; VOLATILE_PLAINTEXT_LEN];
        plaintext[0..8].copy_from_slice(&locator.generation.to_le_bytes());
        plaintext[8..16].copy_from_slice(&locator.index_offset.to_le_bytes());
        plaintext[16..24].copy_from_slice(&locator.index_length.to_le_bytes());
        plaintext[24..56].copy_from_slice(&locator.index_mac);
        fill_random(&mut plaintext[VOLATILE_PAYLOAD_LEN..]);
        encrypt_slot(
            &self.k_index,
            &plaintext,
            &volatile_aad(self.vault_id, self.blob_id, locator.slot_index),
        )
    }

    fn write_volatile_slot(&mut self, locator: &Locator) -> Result<(), VaultError> {
        let slot = self.make_volatile_slot(locator)?;
        let offset = if locator.slot_index == 0 {
            VOLATILE_A_OFFSET
        } else {
            VOLATILE_B_OFFSET
        };
        self.write_all_at(offset, &slot)
    }

    fn prepare_write(
        &self,
        chunks: &[NewChunk],
        completed_files: &[NewFileComplete],
        mut data_tail: u64,
    ) -> Result<WritePlan, VaultError> {
        let mut prepared = Vec::with_capacity(chunks.len());
        let mut index_entries = Vec::new();
        let mut total_chunk_len = 0_u64;

        for chunk in chunks {
            if chunk.plaintext.len() as u64 > MAX_CHUNK_PLAINTEXT_LEN {
                return Err(VaultError::InvalidChunkSize);
            }

            let content_hash = blake2b256(&chunk.plaintext);
            let entry = ChunkEntry {
                file_id: chunk.file_id,
                sequence_number: chunk.sequence_number,
                offset_in_blob: data_tail,
                plaintext_length: chunk.plaintext.len() as u64,
                content_hash,
            };
            let frame = self.encrypt_chunk(&entry, &chunk.plaintext)?;
            total_chunk_len = checked_add(total_chunk_len, frame.len() as u64)?;
            data_tail = checked_add(data_tail, frame.len() as u64)?;
            encode_chunk_entry(&entry, &mut index_entries);
            prepared.push(PreparedChunk { entry, frame });
        }

        for complete in completed_files {
            encode_file_complete_entry(complete, &mut index_entries);
        }

        Ok(WritePlan {
            chunks: prepared,
            index_entries,
            total_chunk_len,
        })
    }

    fn data_tail(&self, index: &BlobIndex) -> Result<u64, VaultError> {
        index
            .chunks
            .iter()
            .try_fold(FRONT_MATTER_LEN, |tail, entry| {
                let chunk_end = checked_add(
                    entry.offset_in_blob,
                    checked_add(entry.plaintext_length, CHUNK_OVERHEAD)?,
                )?;
                Ok(cmp::max(tail, chunk_end))
            })
    }

    fn encrypt_chunk(&self, entry: &ChunkEntry, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        let k_file = self.file_key(entry.file_id)?;
        encrypt_frame(
            &k_file,
            plaintext,
            &chunk_aad(self.vault_id, self.blob_id, entry),
        )
    }

    fn decrypt_chunk(&self, entry: &ChunkEntry, frame: &[u8]) -> Result<Vec<u8>, VaultError> {
        let k_file = self.file_key(entry.file_id)?;
        let plaintext = decrypt_frame(
            &k_file,
            frame,
            &chunk_aad(self.vault_id, self.blob_id, entry),
        )?;
        if plaintext.len() as u64 != entry.plaintext_length {
            return Err(VaultError::AeadDecryptFailed);
        }
        if blake2b256(&plaintext) != entry.content_hash {
            return Err(VaultError::AeadDecryptFailed);
        }
        Ok(plaintext)
    }

    fn file_key(&self, file_id: FileId) -> Result<[u8; 32], VaultError> {
        let hk = Hkdf::<Sha256>::new(Some(&self.vault_id.0), &self.k_data);
        let mut info = Vec::with_capacity(21);
        info.extend_from_slice(b"file/");
        info.extend_from_slice(&file_id.0);
        let mut out = [0_u8; 32];
        hk.expand(&info, &mut out)
            .map_err(|_| VaultError::InvalidMasterKey)?;
        Ok(out)
    }

    fn read_at(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, VaultError> {
        let len: usize = len.try_into().map_err(|_| VaultError::IntegerOverflow)?;
        let mut buf = vec![0_u8; len];
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), VaultError> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(bytes)?;
        Ok(())
    }

    fn write_random_at(&mut self, offset: u64, len: u64) -> Result<(), VaultError> {
        self.file.seek(SeekFrom::Start(offset))?;
        let mut remaining = len;
        let mut buf = [0_u8; 8192];
        while remaining > 0 {
            let n = cmp::min(remaining, buf.len() as u64) as usize;
            fill_random(&mut buf[..n]);
            self.file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        Ok(())
    }

    fn diagnostics_enabled(&self) -> bool {
        diag::diagnostics_enabled(self.config.diagnostics)
    }

    fn log_diag(&self, msg: impl std::fmt::Display) {
        diag::log_line(&self.path, self.blob_id, self.diagnostics_enabled(), msg);
    }
}

impl ExclusiveLock {
    fn acquire(file: &File) -> Result<Self, VaultError> {
        flock(file, libc::LOCK_EX)?;
        Ok(Self(file.as_raw_fd()))
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        let _ = flock_fd(self.0, libc::LOCK_UN);
    }
}

/// Estimated index ciphertext bytes added for one `put_file`-style write (append only).
pub fn estimate_index_bytes_for_file(plaintext_len: u64, max_chunk_size: u64) -> u64 {
    let chunk_count = plaintext_len.div_ceil(max_chunk_size.max(1));
    chunk_count
        .saturating_mul(INDEX_CHUNK_ENTRY_BYTES)
        .saturating_add(INDEX_FILE_COMPLETE_ENTRY_BYTES)
}

impl std::fmt::Display for BlobLayoutStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "file_size:              {}", self.file_size)?;
        writeln!(f, "front_matter:           {}", self.front_matter_bytes)?;
        writeln!(f, "body:                   {}", self.body_bytes)?;
        writeln!(
            f,
            "locator:                generation={}",
            self.locator_generation
        )?;
        writeln!(
            f,
            "chunks:                 count={} plaintext={} frames={} (overhead={})",
            self.chunk_count,
            self.chunk_plaintext_bytes,
            self.chunk_frame_bytes,
            self.chunk_frame_overhead_bytes
        )?;
        writeln!(
            f,
            "gaps (data region):     before_first_chunk={} inter_chunk={} leading_before_index={}",
            self.gap_before_first_chunk_bytes, self.inter_chunk_gap_bytes, self.leading_gap_bytes
        )?;
        writeln!(f, "data_tail:              {}", self.data_tail)?;
        writeln!(
            f,
            "index:                  offset={} length={} (ciphertext=entries_plaintext={})",
            self.index_offset, self.index_length, self.index_entry_plaintext_bytes
        )?;
        writeln!(f, "trailing_gap:           {}", self.trailing_gap_bytes)?;
        writeln!(
            f,
            "body_unclassified:      {} (stale ciphertext / relocation slack)",
            self.body_unclassified_bytes
        )
    }
}

fn validate_config(config: &BlobConfig) -> Result<(), VaultError> {
    checked_add(config.initial_leading_gap, config.initial_trailing_gap)?;
    checked_add(
        config.relocation_leading_padding,
        config.relocation_trailing_padding,
    )?;
    Ok(())
}

fn stable_wrap_aad(vault_id: &VaultId, purpose: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + purpose.len());
    aad.extend_from_slice(&vault_id.0);
    aad.extend_from_slice(purpose.as_bytes());
    aad
}

fn stable_wrap_nonce(
    master_key: &[u8; 32],
    vault_id: &VaultId,
    purpose: &str,
) -> Result<[u8; NONCE_LEN], VaultError> {
    let hk = Hkdf::<Sha256>::new(Some(&vault_id.0), master_key);
    let mut info = b"stable-wrap/".to_vec();
    info.extend_from_slice(purpose.as_bytes());
    let mut nonce = [0_u8; NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .map_err(|_| VaultError::AeadEncryptFailed)?;
    Ok(nonce)
}

fn wrap_stable_key(
    master_key: &[u8; 32],
    vault_id: &VaultId,
    purpose: &str,
    key: &[u8; 32],
) -> Result<[u8; WRAPPED_KEY_LEN], VaultError> {
    let nonce = stable_wrap_nonce(master_key, vault_id, purpose)?;
    let aad = stable_wrap_aad(vault_id, purpose);
    let cipher = <XChaCha20Poly1305 as Poly1305KeyInit>::new(Key::from_slice(master_key).into());
    let wrapped = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: key,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AeadEncryptFailed)?;
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(VaultError::AeadEncryptFailed);
    }
    Ok(copy_array(&wrapped))
}

fn unwrap_stable_key(
    master_key: &[u8; 32],
    vault_id: &VaultId,
    purpose: &str,
    wrapped: &[u8; WRAPPED_KEY_LEN],
) -> Result<[u8; 32], VaultError> {
    let nonce = stable_wrap_nonce(master_key, vault_id, purpose)?;
    let aad = stable_wrap_aad(vault_id, purpose);
    let cipher = <XChaCha20Poly1305 as Poly1305KeyInit>::new(Key::from_slice(master_key).into());
    let key = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: wrapped,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::AeadDecryptFailed)?;
    if key.len() != 32 {
        return Err(VaultError::AeadDecryptFailed);
    }
    Ok(copy_array(&key))
}

fn derive_index_mac_key(k_index: &[u8; 32], blob_id: &BlobId) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&blob_id.0), k_index);
    let mut out = [0_u8; 32];
    hk.expand(b"index-mac", &mut out)
        .expect("32-byte HKDF output is valid");
    out
}

fn compute_index_mac(
    k_mac: &[u8; 32],
    vault_id: &VaultId,
    blob_id: &BlobId,
    generation: u64,
    index_length: u64,
    ciphertext: &[u8],
) -> Result<[u8; 32], VaultError> {
    type Mac256 = blake2::Blake2bMac<U32>;
    let mut mac = <Mac256 as Blake2KeyInit>::new_from_slice(k_mac)
        .map_err(|_| VaultError::AeadEncryptFailed)?;
    Mac::update(&mut mac, &vault_id.0);
    Mac::update(&mut mac, &blob_id.0);
    Mac::update(&mut mac, &generation.to_le_bytes());
    Mac::update(&mut mac, &index_length.to_le_bytes());
    Mac::update(&mut mac, ciphertext);
    let result = mac.finalize().into_bytes();
    Ok(copy_array(&result))
}

fn constant_time_eq32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0_u8;
    for index in 0..32 {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

fn index_stream_xor(
    k_index: &[u8; 32],
    index_nonce: &[u8; NONCE_LEN],
    stream_offset: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let mut out = plaintext.to_vec();
    let mut cipher = XChaCha20::new(k_index.into(), index_nonce.into());
    cipher.seek(stream_offset);
    cipher.apply_keystream(&mut out);
    Ok(out)
}

fn index_stream_decrypt_in_place(
    k_index: &[u8; 32],
    index_nonce: &[u8; NONCE_LEN],
    ciphertext: &mut [u8],
) -> Result<(), VaultError> {
    let mut cipher = XChaCha20::new(k_index.into(), index_nonce.into());
    cipher.apply_keystream(ciphertext);
    Ok(())
}

fn flock(file: &File, op: libc::c_int) -> Result<(), VaultError> {
    flock_fd(file.as_raw_fd(), op)
}

fn flock_fd(fd: libc::c_int, op: libc::c_int) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        let rc = unsafe { libc::flock(fd, op) };
        if rc == 0 {
            Ok(())
        } else {
            Err(VaultError::Io(std::io::Error::last_os_error()))
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (fd, op);
        Err(VaultError::UnsupportedPlatform)
    }
}

fn encrypt_slot(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    encrypt_frame(key, plaintext, aad)
}

fn decrypt_slot(key: &[u8; 32], slot: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    decrypt_frame(key, slot, aad)
}

fn encrypt_frame(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    let cipher = <XChaCha20Poly1305 as Poly1305KeyInit>::new(Key::from_slice(key).into());
    let nonce = <XChaCha20Poly1305 as AeadCore>::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::AeadEncryptFailed)?;
    let mut frame = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

fn decrypt_frame(key: &[u8; 32], frame: &[u8], aad: &[u8]) -> Result<Vec<u8>, VaultError> {
    if frame.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::AeadDecryptFailed);
    }
    let cipher = <XChaCha20Poly1305 as Poly1305KeyInit>::new(Key::from_slice(key).into());
    let nonce = XNonce::from_slice(&frame[..NONCE_LEN]);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &frame[NONCE_LEN..],
                aad,
            },
        )
        .map_err(|_| VaultError::AeadDecryptFailed)
}

fn volatile_aad(vault_id: VaultId, blob_id: BlobId, slot_index: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(33);
    aad.extend_from_slice(&vault_id.0);
    aad.extend_from_slice(&blob_id.0);
    aad.push(slot_index);
    aad
}

fn chunk_aad(vault_id: VaultId, blob_id: BlobId, entry: &ChunkEntry) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&vault_id.0);
    aad.extend_from_slice(&blob_id.0);
    aad.extend_from_slice(&entry.file_id.0);
    aad.extend_from_slice(&entry.sequence_number.to_le_bytes());
    aad.extend_from_slice(&entry.offset_in_blob.to_le_bytes());
    aad
}

fn parse_entries(plaintext: &[u8], index: &mut BlobIndex) -> Result<(), VaultError> {
    let mut pos = 0;
    while pos < plaintext.len() {
        let tag = plaintext[pos];
        pos += 1;

        match tag {
            0x01 => {
                if plaintext.len() - pos < CHUNK_ENTRY_PAYLOAD_LEN {
                    return Err(VaultError::IndexChainBroken);
                }
                let file_id = FileId(copy_array(&plaintext[pos..pos + 16]));
                pos += 16;
                let sequence_number = read_u64(&plaintext[pos..pos + 8]);
                pos += 8;
                let offset_in_blob = read_u64(&plaintext[pos..pos + 8]);
                pos += 8;
                let plaintext_length = read_u64(&plaintext[pos..pos + 8]);
                pos += 8;
                let content_hash = copy_array(&plaintext[pos..pos + 32]);
                pos += 32;
                index.chunks.push(ChunkEntry {
                    file_id,
                    sequence_number,
                    offset_in_blob,
                    plaintext_length,
                    content_hash,
                });
            }
            0x02 => {
                if plaintext.len() - pos < FILE_COMPLETE_PAYLOAD_LEN {
                    return Err(VaultError::IndexChainBroken);
                }
                let file_id = FileId(copy_array(&plaintext[pos..pos + 16]));
                pos += 16;
                let total_chunks = read_u64(&plaintext[pos..pos + 8]);
                pos += 8;
                let full_content_hash = copy_array(&plaintext[pos..pos + 32]);
                pos += 32;
                index.completed_files.push(FileCompleteEntry {
                    file_id,
                    total_chunks,
                    full_content_hash,
                });
            }
            _ => return Err(VaultError::IndexChainBroken),
        }
    }

    Ok(())
}

fn encode_chunk_entry(entry: &ChunkEntry, out: &mut Vec<u8>) {
    out.push(0x01);
    out.extend_from_slice(&entry.file_id.0);
    out.extend_from_slice(&entry.sequence_number.to_le_bytes());
    out.extend_from_slice(&entry.offset_in_blob.to_le_bytes());
    out.extend_from_slice(&entry.plaintext_length.to_le_bytes());
    out.extend_from_slice(&entry.content_hash);
}

fn encode_file_complete_entry(entry: &NewFileComplete, out: &mut Vec<u8>) {
    out.push(0x02);
    out.extend_from_slice(&entry.file_id.0);
    out.extend_from_slice(&entry.total_chunks.to_le_bytes());
    out.extend_from_slice(&entry.full_content_hash);
}

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("32-byte BLAKE2b output is valid");
    hasher.update(bytes);
    hasher
        .finalize_variable(&mut out)
        .expect("fixed output buffer has requested length");
    out
}

fn fill_random(bytes: &mut [u8]) {
    OsRng.fill_bytes(bytes);
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(copy_array(bytes))
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0_u8; N];
    out.copy_from_slice(&bytes[..N]);
    out
}

fn checked_add(a: u64, b: u64) -> Result<u64, VaultError> {
    a.checked_add(b).ok_or(VaultError::IntegerOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vaultblob-core-{name}-{}-{nanos}.blob",
            std::process::id()
        ))
    }

    fn master_key() -> VaultMasterKey {
        VaultMasterKey([7_u8; 32])
    }

    fn vault_id() -> VaultId {
        VaultId([3_u8; 16])
    }

    fn file_id(byte: u8) -> FileId {
        FileId([byte; 16])
    }

    #[test]
    fn stable_slot_wraps_blob_keys_as_nested_aead_frames() {
        let master_key = [9_u8; 32];
        let vault_id = vault_id();
        let k_data = [1_u8; 32];
        let k_index = [2_u8; 32];

        let wrapped_k_data = wrap_stable_key(&master_key, &vault_id, "K_data", &k_data).unwrap();
        let wrapped_k_index = wrap_stable_key(&master_key, &vault_id, "K_index", &k_index).unwrap();
        assert_eq!(wrapped_k_data.len(), WRAPPED_KEY_LEN);
        assert_eq!(wrapped_k_index.len(), WRAPPED_KEY_LEN);
        assert_ne!(wrapped_k_data, wrapped_k_index);

        assert_eq!(
            unwrap_stable_key(&master_key, &vault_id, "K_data", &wrapped_k_data).unwrap(),
            k_data
        );
        assert_eq!(
            unwrap_stable_key(&master_key, &vault_id, "K_index", &wrapped_k_index).unwrap(),
            k_index
        );
    }

    #[test]
    fn index_mac_and_stream_roundtrip() {
        let k_index = [1_u8; 32];
        let index_nonce = [2_u8; NONCE_LEN];
        let vault_id = vault_id();
        let blob_id = BlobId([4_u8; 16]);
        let k_mac = derive_index_mac_key(&k_index, &blob_id);

        let entries = {
            let mut out = Vec::new();
            encode_chunk_entry(
                &ChunkEntry {
                    file_id: file_id(1),
                    sequence_number: 0,
                    offset_in_blob: 4096,
                    plaintext_length: 3,
                    content_hash: [0_u8; 32],
                },
                &mut out,
            );
            out
        };

        let ct = index_stream_xor(&k_index, &index_nonce, 0, &entries).unwrap();
        let mac = compute_index_mac(&k_mac, &vault_id, &blob_id, 1, ct.len() as u64, &ct).unwrap();
        let mac2 = compute_index_mac(&k_mac, &vault_id, &blob_id, 1, ct.len() as u64, &ct).unwrap();
        assert!(constant_time_eq32(&mac, &mac2));

        let mut plain = ct.clone();
        index_stream_decrypt_in_place(&k_index, &index_nonce, &mut plain).unwrap();
        assert_eq!(plain, entries);
    }

    #[test]
    fn writes_reads_and_reopens_multiple_chunks() {
        let path = test_path("roundtrip");
        let config = BlobConfig {
            initial_leading_gap: 256,
            initial_trailing_gap: 256,
            relocation_leading_padding: 512,
            relocation_trailing_padding: 512,
            reader_retry_budget: 2,
            diagnostics: false,
        };

        let mut blob = Blob::open(&path, vault_id(), &master_key(), config.clone()).unwrap();
        let chunks = vec![
            NewChunk {
                file_id: file_id(1),
                sequence_number: 0,
                plaintext: b"hello ".to_vec(),
            },
            NewChunk {
                file_id: file_id(1),
                sequence_number: 1,
                plaintext: b"world".to_vec(),
            },
        ];
        let complete = NewFileComplete {
            file_id: file_id(1),
            total_chunks: 2,
            full_content_hash: blake2b256(b"hello world"),
        };

        let written = blob.write_chunks(&chunks, &[complete]).unwrap();
        assert_eq!(written.entries.len(), 2);
        assert_eq!(blob.read_chunk(&written.entries[0]).unwrap(), b"hello ");
        assert_eq!(blob.read_chunk(&written.entries[1]).unwrap(), b"world");

        drop(blob);
        let mut reopened = Blob::open_existing(&path, vault_id(), &master_key(), config).unwrap();
        let index = reopened.read_index().unwrap();
        assert_eq!(index.chunks.len(), 2);
        assert_eq!(index.completed_files.len(), 1);
        assert_eq!(reopened.read_chunk_by_id(file_id(1), 1).unwrap(), b"world");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn relocates_index_when_gaps_are_too_small() {
        let path = test_path("relocate");
        let config = BlobConfig {
            initial_leading_gap: 1,
            initial_trailing_gap: 1,
            relocation_leading_padding: 64,
            relocation_trailing_padding: 64,
            reader_retry_budget: 2,
            diagnostics: false,
        };

        let mut blob = Blob::open(&path, vault_id(), &master_key(), config).unwrap();
        let first = blob
            .write_chunks(
                &[NewChunk {
                    file_id: file_id(2),
                    sequence_number: 0,
                    plaintext: vec![9; 128],
                }],
                &[],
            )
            .unwrap();
        let second = blob
            .write_chunks(
                &[NewChunk {
                    file_id: file_id(2),
                    sequence_number: 1,
                    plaintext: vec![8; 128],
                }],
                &[],
            )
            .unwrap();

        assert_eq!(blob.read_chunk(&first.entries[0]).unwrap(), vec![9; 128]);
        assert_eq!(blob.read_chunk(&second.entries[0]).unwrap(), vec![8; 128]);
        assert_eq!(blob.read_index().unwrap().chunks.len(), 2);

        let _ = std::fs::remove_file(path);
    }
}
