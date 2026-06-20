use std::cmp;
use std::collections::BTreeMap;
use std::path::PathBuf;

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

use crate::frontmatter::FrontMatter;

use crate::blob::{Blob, BlobIndex, BlobLayoutStats, NewChunk, NewFileComplete};
use crate::error::VaultError;
use crate::types::{BlobId, ChunkEntry, FileCompleteEntry, FileId, VaultId};

const CHUNK_FRAME_OVERHEAD: u64 = 40;
const CHUNK_ENTRY_WIRE_LEN: u64 = 73;
const FILE_COMPLETE_ENTRY_WIRE_LEN: u64 = 57;
const SPLIT_CHUNK_WRITE_OVERHEAD: u64 =
    CHUNK_FRAME_OVERHEAD + CHUNK_ENTRY_WIRE_LEN + FILE_COMPLETE_ENTRY_WIRE_LEN;

/// Write and orchestration policy for a vault.
#[derive(Clone, Debug)]
pub struct VaultConfig {
    /// Maximum plaintext bytes per chunk produced by vault writes.
    pub max_chunk_size: usize,
    /// Soft maximum estimated physical bytes per blob before selecting another blob.
    pub max_blob_size: u64,
    /// Permit one logical file to be distributed across multiple blobs.
    pub split_files_across_blobs: bool,
    /// Prefer rotating chunks across eligible blobs when splitting is enabled.
    pub stripe_chunks_across_blobs: bool,
    /// Keep blob indexes cached and update them after vault writes.
    pub cache_indexes_on_open: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            max_chunk_size: 4 * 1024 * 1024,
            max_blob_size: 1024 * 1024 * 1024,
            split_files_across_blobs: false,
            stripe_chunks_across_blobs: false,
            cache_indexes_on_open: true,
        }
    }
}

/// A chunk entry plus the blob that owns it.
#[derive(Clone, Debug)]
pub struct LocatedChunkEntry {
    pub blob_id: BlobId,
    pub entry: ChunkEntry,
}

/// A complete-file marker plus the blob that contains that marker.
#[derive(Clone, Debug)]
pub struct LocatedFileCompleteEntry {
    pub blob_id: BlobId,
    pub entry: FileCompleteEntry,
}

/// The vault's cached view of all blob indexes.
#[derive(Clone, Debug, Default)]
pub struct VaultIndex {
    pub chunks: Vec<LocatedChunkEntry>,
    pub completed_files: Vec<LocatedFileCompleteEntry>,
}

/// Stateful read cursor for a logical file.
#[derive(Clone, Copy, Debug)]
pub struct VaultFileCursor {
    file_id: FileId,
    position: u64,
}

impl VaultFileCursor {
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn seek(&mut self, position: u64) {
        self.position = position;
    }
}

/// Minimal watcher registration hook. Implementations decide how blob changes
/// are detected; the vault only exposes blob identities and refresh callbacks.
pub trait BlobWatchRegistrar {
    fn watch_blob(&mut self, blob_id: BlobId);
}

type ChangeCallback = Box<dyn FnMut(BlobId, &BlobIndex)>;

pub struct Vault {
    vault_id: VaultId,
    blobs: Vec<Blob>,
    config: VaultConfig,
    index: VaultIndex,
    change_callbacks: Vec<ChangeCallback>,
    next_blob_cursor: usize,
}

impl Vault {
    /// Open a vault from already-opened blobs. The vault performs no direct disk
    /// or crypto operations; those remain owned by `Blob`.
    pub fn open(
        vault_id: VaultId,
        blobs: Vec<Blob>,
        config: VaultConfig,
    ) -> Result<Self, VaultError> {
        validate_config(&config)?;
        if blobs.is_empty() {
            return Err(VaultError::InvalidConfig);
        }
        if blobs.iter().any(|blob| blob.vault_id != vault_id) {
            return Err(VaultError::InvalidConfig);
        }

        let mut vault = Self {
            vault_id,
            blobs,
            config,
            index: VaultIndex::default(),
            change_callbacks: Vec::new(),
            next_blob_cursor: 0,
        };

        if vault.config.cache_indexes_on_open {
            vault.refresh_indexes()?;
        }

        Ok(vault)
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn blob_ids(&self) -> Vec<BlobId> {
        self.blobs.iter().map(|b| b.blob_id).collect()
    }

    /// Layout stats for every blob in the vault (reads each canonical index).
    pub fn layout_stats(&mut self) -> Result<Vec<(BlobId, PathBuf, BlobLayoutStats)>, VaultError> {
        let mut out = Vec::with_capacity(self.blobs.len());
        for blob in &mut self.blobs {
            out.push((blob.blob_id, blob.path.to_path_buf(), blob.layout_stats()?));
        }
        Ok(out)
    }

    pub fn cached_index(&self) -> &VaultIndex {
        &self.index
    }

    /// Register each blob with an external watcher implementation.
    pub fn register_blob_watches<R: BlobWatchRegistrar>(&self, registrar: &mut R) {
        for blob in &self.blobs {
            registrar.watch_blob(blob.blob_id);
        }
    }

    /// Add a callback invoked after `handle_blob_changed` refreshes a blob.
    pub fn on_blob_changed<F>(&mut self, callback: F)
    where
        F: FnMut(BlobId, &BlobIndex) + 'static,
    {
        self.change_callbacks.push(Box::new(callback));
    }

    /// External watchers call this when one blob changes. The vault refreshes
    /// only that blob's cached index and then runs registered callbacks.
    pub fn handle_blob_changed(&mut self, blob_id: BlobId) -> Result<(), VaultError> {
        let blob_index = self.refresh_blob_index(blob_id)?;
        for callback in &mut self.change_callbacks {
            callback(blob_id, &blob_index);
        }
        Ok(())
    }

    pub fn refresh_indexes(&mut self) -> Result<(), VaultError> {
        self.index = VaultIndex::default();
        for blob_index in 0..self.blobs.len() {
            let blob_id = self.blobs[blob_index].blob_id;
            let index = self.blobs[blob_index].refresh_committed_snapshot()?;
            self.replace_cached_blob_index(blob_id, &index);
        }
        Ok(())
    }

    /// Attach a newly created blob to this vault and load its (empty) index into the cache.
    pub fn append_blob(&mut self, blob: Blob) -> Result<(), VaultError> {
        if blob.vault_id != self.vault_id {
            return Err(VaultError::InvalidConfig);
        }
        let blob_id = blob.blob_id;
        self.blobs.push(blob);
        let blob_index = self.blobs.len() - 1;
        let index = self.blobs[blob_index].refresh_committed_snapshot()?;
        self.replace_cached_blob_index(blob_id, &index);
        Ok(())
    }

    pub fn put_file(&mut self, file_id: FileId, contents: &[u8]) -> Result<(), VaultError> {
        if self
            .index
            .chunks
            .iter()
            .any(|chunk| chunk.entry.file_id == file_id)
        {
            return Err(VaultError::FileAlreadyExists);
        }

        let chunks = self.plan_file_chunks(file_id, contents)?;
        let complete = NewFileComplete {
            file_id,
            total_chunks: chunks.len() as u64,
            full_content_hash: blake2b256(contents),
        };

        let mut chunks_by_blob: BTreeMap<usize, Vec<NewChunk>> = BTreeMap::new();
        for (blob_index, chunk) in chunks {
            chunks_by_blob.entry(blob_index).or_default().push(chunk);
        }

        let complete_blob_index = chunks_by_blob
            .keys()
            .last()
            .copied()
            .ok_or(VaultError::InvalidConfig)?;

        for (blob_index, blob_chunks) in chunks_by_blob {
            let completes = if blob_index == complete_blob_index {
                std::slice::from_ref(&complete)
            } else {
                &[]
            };
            let write_result = self.blobs[blob_index].write_chunks(&blob_chunks, completes)?;
            let blob_id = self.blobs[blob_index].blob_id;
            self.replace_cached_blob_index(blob_id, &write_result.index);
        }

        Ok(())
    }

    pub fn read_file(&mut self, file_id: FileId) -> Result<Vec<u8>, VaultError> {
        let size = self.file_size(file_id)?;
        let contents = self.read_file_range(file_id, 0, size)?;
        let complete = self.latest_complete(file_id)?;
        if blake2b256(&contents) != complete.entry.full_content_hash {
            return Err(VaultError::FileHashMismatch);
        }
        Ok(contents)
    }

    pub fn read_file_range(
        &mut self,
        file_id: FileId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, VaultError> {
        self.ensure_file_complete(file_id)?;
        let chunks = self.ordered_file_chunks(file_id)?;
        let file_size = chunks.iter().try_fold(0_u64, |acc, chunk| {
            checked_add(acc, chunk.entry.plaintext_length)
        })?;

        if offset >= file_size || length == 0 {
            return Ok(Vec::new());
        }

        let end = cmp::min(checked_add(offset, length)?, file_size);
        let mut out = Vec::with_capacity((end - offset).try_into().unwrap_or(usize::MAX));
        let mut chunk_start = 0_u64;

        for chunk in chunks {
            let chunk_end = checked_add(chunk_start, chunk.entry.plaintext_length)?;
            if chunk_end <= offset {
                chunk_start = chunk_end;
                continue;
            }
            if chunk_start >= end {
                break;
            }

            let blob_index = self.blob_position(chunk.blob_id)?;
            let plaintext = self.blobs[blob_index].read_chunk(&chunk.entry)?;
            let start_in_chunk = offset.saturating_sub(chunk_start) as usize;
            let end_in_chunk = (cmp::min(end, chunk_end) - chunk_start) as usize;
            out.extend_from_slice(&plaintext[start_in_chunk..end_in_chunk]);
            chunk_start = chunk_end;
        }

        Ok(out)
    }

    pub fn open_file(&self, file_id: FileId) -> Result<VaultFileCursor, VaultError> {
        self.ensure_file_complete(file_id)?;
        Ok(VaultFileCursor {
            file_id,
            position: 0,
        })
    }

    pub fn read_from_file(
        &mut self,
        cursor: &mut VaultFileCursor,
        length: u64,
    ) -> Result<Vec<u8>, VaultError> {
        let bytes = self.read_file_range(cursor.file_id, cursor.position, length)?;
        cursor.position = checked_add(cursor.position, bytes.len() as u64)?;
        Ok(bytes)
    }

    pub fn file_size(&self, file_id: FileId) -> Result<u64, VaultError> {
        let chunks = self.ordered_file_chunks(file_id)?;
        chunks.iter().try_fold(0_u64, |acc, chunk| {
            checked_add(acc, chunk.entry.plaintext_length)
        })
    }

    pub fn file_chunks(&self, file_id: FileId) -> Result<Vec<LocatedChunkEntry>, VaultError> {
        self.ordered_file_chunks(file_id)
    }

    fn refresh_blob_index(&mut self, blob_id: BlobId) -> Result<BlobIndex, VaultError> {
        let blob_index = self.blob_position(blob_id)?;
        let index = self.blobs[blob_index].read_index()?;
        self.replace_cached_blob_index(blob_id, &index);
        Ok(index)
    }

    fn replace_cached_blob_index(&mut self, blob_id: BlobId, index: &BlobIndex) {
        self.index.chunks.retain(|chunk| chunk.blob_id != blob_id);
        self.index
            .completed_files
            .retain(|entry| entry.blob_id != blob_id);

        self.index.chunks.extend(
            index
                .chunks
                .iter()
                .cloned()
                .map(|entry| LocatedChunkEntry { blob_id, entry }),
        );
        self.index.completed_files.extend(
            index
                .completed_files
                .iter()
                .cloned()
                .map(|entry| LocatedFileCompleteEntry { blob_id, entry }),
        );
    }

    fn plan_file_chunks(
        &mut self,
        file_id: FileId,
        contents: &[u8],
    ) -> Result<Vec<(usize, NewChunk)>, VaultError> {
        let mut chunks = Vec::new();
        let mut sequence_number = 0_u64;

        if !self.config.split_files_across_blobs {
            let total_chunks = cmp::max(1, contents.len().div_ceil(self.config.max_chunk_size));
            let write_size =
                self.estimated_write_size(contents.len() as u64, total_chunks as u64)?;
            let blob_index = self.choose_blob(write_size)?;

            if contents.is_empty() {
                chunks.push((
                    blob_index,
                    NewChunk {
                        file_id,
                        sequence_number,
                        plaintext: Vec::new(),
                    },
                ));
                return Ok(chunks);
            }

            for plaintext in contents.chunks(self.config.max_chunk_size) {
                chunks.push((
                    blob_index,
                    NewChunk {
                        file_id,
                        sequence_number,
                        plaintext: plaintext.to_vec(),
                    },
                ));
                sequence_number = checked_add(sequence_number, 1)?;
            }

            return Ok(chunks);
        }

        let chunk_size = self.effective_chunk_size()?;
        let mut planned: BTreeMap<usize, u64> = BTreeMap::new();

        if contents.is_empty() {
            let blob_index =
                self.choose_blob_with_planned(&planned, self.estimated_chunk_write_size(0)?)?;
            self.record_planned_write(
                &mut planned,
                blob_index,
                self.estimated_chunk_write_size(0)?,
            );
            chunks.push((
                blob_index,
                NewChunk {
                    file_id,
                    sequence_number,
                    plaintext: Vec::new(),
                },
            ));
            self.finalize_planned_file_complete(&mut planned)?;
            return Ok(chunks);
        }

        for plaintext in contents.chunks(chunk_size) {
            let chunk_estimate = self.estimated_chunk_write_size(plaintext.len() as u64)?;
            let blob_index = self.choose_blob_with_planned(&planned, chunk_estimate)?;
            self.record_planned_write(&mut planned, blob_index, chunk_estimate);
            chunks.push((
                blob_index,
                NewChunk {
                    file_id,
                    sequence_number,
                    plaintext: plaintext.to_vec(),
                },
            ));
            sequence_number = checked_add(sequence_number, 1)?;
        }

        self.finalize_planned_file_complete(&mut planned)?;

        Ok(chunks)
    }

    fn record_planned_write(
        &self,
        planned: &mut BTreeMap<usize, u64>,
        blob_index: usize,
        bytes: u64,
    ) {
        *planned.entry(blob_index).or_default() += bytes;
    }

    fn finalize_planned_file_complete(
        &self,
        planned: &mut BTreeMap<usize, u64>,
    ) -> Result<(), VaultError> {
        let Some(&complete_blob_index) = planned.keys().max() else {
            return Ok(());
        };
        *planned.entry(complete_blob_index).or_default() += FILE_COMPLETE_ENTRY_WIRE_LEN;
        for (&blob_index, &planned_bytes) in planned.iter() {
            let estimated_after =
                checked_add(self.blob_estimated_size(blob_index)?, planned_bytes)?;
            if estimated_after > self.config.max_blob_size {
                return Err(VaultError::NoWritableBlob);
            }
        }
        Ok(())
    }

    fn blob_estimated_size_with_planned(
        &self,
        blob_index: usize,
        planned: &BTreeMap<usize, u64>,
    ) -> Result<u64, VaultError> {
        let planned_bytes = planned.get(&blob_index).copied().unwrap_or(0);
        checked_add(self.blob_estimated_size(blob_index)?, planned_bytes)
    }

    fn choose_blob_with_planned(
        &mut self,
        planned: &BTreeMap<usize, u64>,
        estimated_new_bytes: u64,
    ) -> Result<usize, VaultError> {
        self.choose_blob_inner(planned, estimated_new_bytes)
    }

    fn choose_blob(&mut self, estimated_new_bytes: u64) -> Result<usize, VaultError> {
        self.choose_blob_inner(&BTreeMap::new(), estimated_new_bytes)
    }

    fn choose_blob_inner(
        &mut self,
        planned: &BTreeMap<usize, u64>,
        estimated_new_bytes: u64,
    ) -> Result<usize, VaultError> {
        if self.blobs.is_empty() {
            return Err(VaultError::NoWritableBlob);
        }

        if !self.config.split_files_across_blobs && estimated_new_bytes > self.config.max_blob_size
        {
            return Err(VaultError::FileExceedsBlobCapacity);
        }

        let start = if self.config.split_files_across_blobs {
            if self.config.stripe_chunks_across_blobs {
                self.next_blob_cursor % self.blobs.len()
            } else {
                0
            }
        } else {
            self.next_blob_cursor % self.blobs.len()
        };

        for offset in 0..self.blobs.len() {
            let index = (start + offset) % self.blobs.len();
            let estimated_after = checked_add(
                self.blob_estimated_size_with_planned(index, planned)?,
                estimated_new_bytes,
            )?;
            if estimated_after <= self.config.max_blob_size {
                self.next_blob_cursor = (index + 1) % self.blobs.len();
                return Ok(index);
            }
        }

        Err(VaultError::NoWritableBlob)
    }

    fn effective_chunk_size(&self) -> Result<usize, VaultError> {
        if self.config.max_blob_size <= SPLIT_CHUNK_WRITE_OVERHEAD {
            return Err(VaultError::InvalidConfig);
        }
        let max_plaintext = (self.config.max_blob_size - SPLIT_CHUNK_WRITE_OVERHEAD) as usize;
        let chunk_size = cmp::min(self.config.max_chunk_size, max_plaintext);
        if chunk_size == 0 {
            return Err(VaultError::InvalidConfig);
        }
        Ok(chunk_size)
    }

    fn estimated_chunk_write_size(&self, plaintext_len: u64) -> Result<u64, VaultError> {
        checked_add(
            plaintext_len,
            checked_add(CHUNK_FRAME_OVERHEAD, CHUNK_ENTRY_WIRE_LEN)?,
        )
    }

    fn estimated_write_size(
        &self,
        plaintext_len: u64,
        chunk_count: u64,
    ) -> Result<u64, VaultError> {
        let chunk_frame_overhead = checked_mul(chunk_count, CHUNK_FRAME_OVERHEAD)?;
        let chunk_index_entries = checked_mul(chunk_count, CHUNK_ENTRY_WIRE_LEN)?;
        checked_add(
            checked_add(plaintext_len, chunk_frame_overhead)?,
            checked_add(chunk_index_entries, FILE_COMPLETE_ENTRY_WIRE_LEN)?,
        )
    }

    fn blob_estimated_size(&self, blob_index: usize) -> Result<u64, VaultError> {
        let blob_id = self.blobs[blob_index].blob_id;
        let chunks_size = self
            .index
            .chunks
            .iter()
            .filter(|chunk| chunk.blob_id == blob_id)
            .try_fold(0_u64, |acc, chunk| {
                checked_add(
                    acc,
                    checked_add(chunk.entry.plaintext_length, CHUNK_FRAME_OVERHEAD)?,
                )
            })?;

        let chunk_entries = self
            .index
            .chunks
            .iter()
            .filter(|chunk| chunk.blob_id == blob_id)
            .count() as u64;
        let complete_entries = self
            .index
            .completed_files
            .iter()
            .filter(|entry| entry.blob_id == blob_id)
            .count() as u64;
        let index_size = checked_add(
            checked_mul(chunk_entries, CHUNK_ENTRY_WIRE_LEN)?,
            checked_mul(complete_entries, FILE_COMPLETE_ENTRY_WIRE_LEN)?,
        )?;

        checked_add(chunks_size, index_size)
    }

    fn ensure_file_complete(&self, file_id: FileId) -> Result<(), VaultError> {
        let chunk_count = self
            .index
            .chunks
            .iter()
            .filter(|chunk| chunk.entry.file_id == file_id)
            .count() as u64;

        if chunk_count == 0 {
            return Err(VaultError::FileNotFound);
        }

        let complete = self.latest_complete(file_id)?;

        if complete.entry.total_chunks != chunk_count {
            return Err(VaultError::IncompleteFile);
        }

        Ok(())
    }

    fn latest_complete(&self, file_id: FileId) -> Result<&LocatedFileCompleteEntry, VaultError> {
        self.index
            .completed_files
            .iter()
            .filter(|entry| entry.entry.file_id == file_id)
            .max_by_key(|entry| entry.entry.total_chunks)
            .ok_or(VaultError::IncompleteFile)
    }

    fn ordered_file_chunks(&self, file_id: FileId) -> Result<Vec<LocatedChunkEntry>, VaultError> {
        let mut chunks: Vec<_> = self
            .index
            .chunks
            .iter()
            .filter(|chunk| chunk.entry.file_id == file_id)
            .cloned()
            .collect();

        if chunks.is_empty() {
            return Err(VaultError::FileNotFound);
        }

        chunks.sort_by_key(|chunk| chunk.entry.sequence_number);
        for (expected, chunk) in chunks.iter().enumerate() {
            if chunk.entry.sequence_number != expected as u64 {
                return Err(VaultError::IncompleteFile);
            }
        }
        Ok(chunks)
    }

    fn blob_position(&self, blob_id: BlobId) -> Result<usize, VaultError> {
        self.blobs
            .iter()
            .position(|blob| blob.blob_id == blob_id)
            .ok_or(VaultError::BlobNotFound)
    }
}

fn validate_config(config: &VaultConfig) -> Result<(), VaultError> {
    if config.max_chunk_size == 0 || config.max_blob_size == 0 {
        return Err(VaultError::InvalidConfig);
    }
    Ok(())
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

fn checked_add(a: u64, b: u64) -> Result<u64, VaultError> {
    a.checked_add(b).ok_or(VaultError::IntegerOverflow)
}

fn checked_mul(a: u64, b: u64) -> Result<u64, VaultError> {
    a.checked_mul(b).ok_or(VaultError::IntegerOverflow)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::rc::Rc;

    use crate::{BlobConfig, VaultMasterKey};

    use super::*;

    struct RecordingRegistrar {
        blob_ids: Vec<BlobId>,
    }

    impl BlobWatchRegistrar for RecordingRegistrar {
        fn watch_blob(&mut self, blob_id: BlobId) {
            self.blob_ids.push(blob_id);
        }
    }

    fn test_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vaultblob-core-vault-{name}-{}-{nanos}.blob",
            std::process::id()
        ))
    }

    fn master_key() -> VaultMasterKey {
        VaultMasterKey([11_u8; 32])
    }

    fn vault_id() -> VaultId {
        VaultId([13_u8; 16])
    }

    fn file_id(byte: u8) -> FileId {
        FileId([byte; 16])
    }

    fn blob(path: &PathBuf) -> Blob {
        Blob::open(
            path,
            Some(vault_id()),
            &master_key(),
            BlobConfig {
                initial_leading_gap: 128,
                initial_trailing_gap: 128,
                relocation_leading_padding: 256,
                relocation_trailing_padding: 256,
                reader_retry_budget: 2,
                diagnostics: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn writes_reads_and_partial_reads_file() {
        let path = test_path("single");
        let mut vault = Vault::open(
            vault_id(),
            vec![blob(&path)],
            VaultConfig {
                max_chunk_size: 5,
                max_blob_size: 1024,
                split_files_across_blobs: false,
                stripe_chunks_across_blobs: false,
                cache_indexes_on_open: true,
            },
        )
        .unwrap();

        vault.put_file(file_id(1), b"hello world").unwrap();

        assert_eq!(vault.file_size(file_id(1)).unwrap(), 11);
        assert_eq!(vault.read_file(file_id(1)).unwrap(), b"hello world");
        assert_eq!(vault.read_file_range(file_id(1), 3, 5).unwrap(), b"lo wo");
        let mut cursor = vault.open_file(file_id(1)).unwrap();
        cursor.seek(6);
        assert_eq!(vault.read_from_file(&mut cursor, 5).unwrap(), b"world");
        assert_eq!(cursor.position(), 11);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn splits_a_file_larger_than_max_blob_size_across_blobs() {
        let path_a = test_path("split-large-a");
        let path_b = test_path("split-large-b");
        let mut vault = Vault::open(
            vault_id(),
            vec![blob(&path_a)],
            VaultConfig {
                max_chunk_size: 4 * 1024 * 1024,
                max_blob_size: 1024 * 1024,
                split_files_across_blobs: true,
                stripe_chunks_across_blobs: true,
                cache_indexes_on_open: true,
            },
        )
        .unwrap();

        let payload = vec![7_u8; 1_498_269];
        match vault.put_file(file_id(9), &payload) {
            Ok(()) => {}
            Err(VaultError::NoWritableBlob) => {
                vault.append_blob(blob(&path_b)).unwrap();
                vault.put_file(file_id(9), &payload).unwrap();
            }
            Err(err) => panic!("unexpected error: {err:?}"),
        }

        assert_eq!(vault.read_file(file_id(9)).unwrap(), payload);
        let located = vault.file_chunks(file_id(9)).unwrap();
        assert_eq!(located.len(), 2);
        assert_ne!(located[0].blob_id, located[1].blob_id);

        let _ = std::fs::remove_file(path_a);
        let _ = std::fs::remove_file(path_b);
    }

    #[test]
    fn rotates_whole_files_to_a_new_blob_when_max_blob_size_is_reached() {
        let path_a = test_path("rotate-a");
        let path_b = test_path("rotate-b");
        let mut vault = Vault::open(
            vault_id(),
            vec![blob(&path_a)],
            VaultConfig {
                max_chunk_size: 1024,
                max_blob_size: 2048,
                split_files_across_blobs: false,
                stripe_chunks_across_blobs: false,
                cache_indexes_on_open: true,
            },
        )
        .unwrap();

        vault.put_file(file_id(1), &[1_u8; 1000]).unwrap();
        assert!(matches!(
            vault.put_file(file_id(2), &[2_u8; 1000]),
            Err(VaultError::NoWritableBlob)
        ));
        vault.append_blob(blob(&path_b)).unwrap();
        vault.put_file(file_id(2), &[2_u8; 1000]).unwrap();

        assert_eq!(vault.blob_ids().len(), 2);
        assert_eq!(vault.file_chunks(file_id(1)).unwrap().len(), 1);
        assert_eq!(vault.file_chunks(file_id(2)).unwrap().len(), 1);
        assert_ne!(
            vault.file_chunks(file_id(1)).unwrap()[0].blob_id,
            vault.file_chunks(file_id(2)).unwrap()[0].blob_id,
        );

        let _ = std::fs::remove_file(path_a);
        let _ = std::fs::remove_file(path_b);
    }

    #[test]
    fn can_split_one_file_across_blobs_and_refresh_from_watcher_callback() {
        let path_a = test_path("a");
        let path_b = test_path("b");
        let mut vault = Vault::open(
            vault_id(),
            vec![blob(&path_a), blob(&path_b)],
            VaultConfig {
                max_chunk_size: 4,
                max_blob_size: 500,
                split_files_across_blobs: true,
                stripe_chunks_across_blobs: true,
                cache_indexes_on_open: true,
            },
        )
        .unwrap();

        let mut registrar = RecordingRegistrar {
            blob_ids: Vec::new(),
        };
        vault.register_blob_watches(&mut registrar);
        assert_eq!(registrar.blob_ids.len(), 2);

        let changed = Rc::new(RefCell::new(Vec::new()));
        let changed_for_callback = Rc::clone(&changed);
        vault.on_blob_changed(move |blob_id, index| {
            changed_for_callback
                .borrow_mut()
                .push((blob_id, index.chunks.len()));
        });

        vault.put_file(file_id(2), b"abcdefghijkl").unwrap();
        assert_eq!(vault.read_file_range(file_id(2), 4, 4).unwrap(), b"efgh");

        let blob_ids = vault.blob_ids();
        let distribution: HashMap<_, _> = vault.file_chunks(file_id(2)).unwrap().into_iter().fold(
            HashMap::<BlobId, usize>::new(),
            |mut acc, chunk| {
                *acc.entry(chunk.blob_id).or_default() += 1;
                acc
            },
        );
        assert_eq!(distribution.len(), 2);

        vault.handle_blob_changed(blob_ids[0]).unwrap();
        assert_eq!(changed.borrow().len(), 1);

        let _ = std::fs::remove_file(path_a);
        let _ = std::fs::remove_file(path_b);
    }
}
