use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

use vaultblob_core::{
    BlobId, FileId, Vault, VaultConfig, VaultError, VaultId, VaultMasterKey,
};

mod vault_io;

// ---------------------------------------------------------------------------
// Send wrapper – Vault carries `Box<dyn FnMut>` closures that are not
// automatically `Send`, but we guarantee single-threaded access behind a
// Mutex so this is safe.
// ---------------------------------------------------------------------------

struct SendVault(Vault);
unsafe impl Send for SendVault {}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

const VAULTBLOB_OK: i32 = 0;
const VAULTBLOB_ERR_IO: i32 = -1;
const VAULTBLOB_ERR_AEAD_DECRYPT: i32 = -2;
const VAULTBLOB_ERR_AEAD_ENCRYPT: i32 = -3;
const VAULTBLOB_ERR_INDEX_CHAIN: i32 = -4;
const VAULTBLOB_ERR_TAIL_HASH: i32 = -5;
const VAULTBLOB_ERR_INDEX_MAC: i32 = -6;
const VAULTBLOB_ERR_NO_LOCATOR: i32 = -7;
const VAULTBLOB_ERR_INVALID_KEY: i32 = -8;
const VAULTBLOB_ERR_INVALID_CFG: i32 = -9;
const VAULTBLOB_ERR_INVALID_CHUNK: i32 = -10;
const VAULTBLOB_ERR_FILE_NOT_FOUND: i32 = -11;
const VAULTBLOB_ERR_INCOMPLETE: i32 = -12;
const VAULTBLOB_ERR_FILE_EXISTS: i32 = -13;
const VAULTBLOB_ERR_HASH_MISMATCH: i32 = -14;
const VAULTBLOB_ERR_BLOB_NOT_FOUND: i32 = -15;
const VAULTBLOB_ERR_NO_WRITABLE: i32 = -16;
const VAULTBLOB_ERR_EXCEEDS_CAP: i32 = -17;
const VAULTBLOB_ERR_INT_OVERFLOW: i32 = -18;
const VAULTBLOB_ERR_UNSUPPORTED: i32 = -19;
const VAULTBLOB_ERR_RETRY_EXCEEDED: i32 = -20;
const VAULTBLOB_ERR_INVALID_SESSION: i32 = -21;
const VAULTBLOB_ERR_BUF_TOO_SMALL: i32 = -23;
const VAULTBLOB_ERR_INVALID_ARG: i32 = -24;

fn vault_error_code(err: &VaultError) -> i32 {
    match err {
        VaultError::Io(_) => VAULTBLOB_ERR_IO,
        VaultError::AeadDecryptFailed => VAULTBLOB_ERR_AEAD_DECRYPT,
        VaultError::AeadEncryptFailed => VAULTBLOB_ERR_AEAD_ENCRYPT,
        VaultError::IndexChainBroken => VAULTBLOB_ERR_INDEX_CHAIN,
        VaultError::TailHashMismatch => VAULTBLOB_ERR_TAIL_HASH,
        VaultError::IndexMacMismatch => VAULTBLOB_ERR_INDEX_MAC,
        VaultError::NoValidLocator => VAULTBLOB_ERR_NO_LOCATOR,
        VaultError::InvalidMasterKey => VAULTBLOB_ERR_INVALID_KEY,
        VaultError::InvalidConfig => VAULTBLOB_ERR_INVALID_CFG,
        VaultError::InvalidChunkSize => VAULTBLOB_ERR_INVALID_CHUNK,
        VaultError::FileNotFound => VAULTBLOB_ERR_FILE_NOT_FOUND,
        VaultError::IncompleteFile => VAULTBLOB_ERR_INCOMPLETE,
        VaultError::FileAlreadyExists => VAULTBLOB_ERR_FILE_EXISTS,
        VaultError::FileHashMismatch => VAULTBLOB_ERR_HASH_MISMATCH,
        VaultError::BlobNotFound => VAULTBLOB_ERR_BLOB_NOT_FOUND,
        VaultError::NoWritableBlob => VAULTBLOB_ERR_NO_WRITABLE,
        VaultError::FileExceedsBlobCapacity => VAULTBLOB_ERR_EXCEEDS_CAP,
        VaultError::IntegerOverflow => VAULTBLOB_ERR_INT_OVERFLOW,
        VaultError::UnsupportedPlatform => VAULTBLOB_ERR_UNSUPPORTED,
        VaultError::RetryBudgetExceeded => VAULTBLOB_ERR_RETRY_EXCEEDED,
    }
}

// ---------------------------------------------------------------------------
// Result types — all value types, no pointers
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vaultblob_result_t {
    pub code: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vaultblob_u64_result_t {
    pub code: i32,
    pub value: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vaultblob_size_result_t {
    pub code: i32,
    pub value: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vaultblob_hex_result_t {
    pub code: i32,
    pub value: [u8; 37],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vaultblob_chunk_info_t {
    pub blob_id_hex: [u8; 37],
    pub sequence_number: u64,
    pub offset_in_blob: u64,
    pub plaintext_length: u64,
    pub content_hash: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct vaultblob_chunk_info_result_t {
    pub code: i32,
    pub value: vaultblob_chunk_info_t,
}

// ---------------------------------------------------------------------------
// UUID hex formatting helpers
// ---------------------------------------------------------------------------

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn format_uuid_hex(bytes: &[u8; 16]) -> [u8; 37] {
    let mut out = [0u8; 37];
    let mut oi = 0usize;
    let mut bi = 0usize;
    while bi < 16 {
        if oi == 8 || oi == 13 || oi == 18 || oi == 23 {
            out[oi] = b'-';
            oi += 1;
        }
        out[oi] = HEX_CHARS[(bytes[bi] >> 4) as usize];
        out[oi + 1] = HEX_CHARS[(bytes[bi] & 0xf) as usize];
        oi += 2;
        bi += 1;
    }
    out
}

fn format_file_id_hex(id: FileId) -> [u8; 37] {
    format_uuid_hex(&id.0)
}

fn format_blob_id_hex(id: BlobId) -> [u8; 37] {
    format_uuid_hex(&id.0)
}

fn format_vault_id_hex(id: VaultId) -> [u8; 37] {
    format_uuid_hex(&id.0)
}

fn parse_file_id_from_str(s: &str) -> Result<FileId, i32> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(VAULTBLOB_ERR_FILE_NOT_FOUND);
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| VAULTBLOB_ERR_FILE_NOT_FOUND)?;
    }
    Ok(FileId(bytes))
}

// ---------------------------------------------------------------------------
// Session registry — uses Arc so we can release the registry lock before
// locking the vault.
// ---------------------------------------------------------------------------

struct Session {
    vault: Arc<Mutex<SendVault>>,
    vault_dir: PathBuf,
    vault_id: VaultId,
    master_key: VaultMasterKey,
}

static SESSIONS: LazyLock<Mutex<HashMap<u64, Session>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Look up a session and return a clone of the vault Arc + extracted data.
/// The sessions lock is released by scope exit before calling `f`, so vault
/// I/O does not hold up session bookkeeping.
fn with_vault<F, R>(session_id: u64, f: F) -> R
where
    F: FnOnce(i32, Option<(Arc<Mutex<SendVault>>, PathBuf, VaultId, VaultMasterKey)>) -> R,
{
    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            return f(VAULTBLOB_ERR_IO, None);
        }
    };
    let session = match sessions.get(&session_id) {
        Some(s) => s,
        None => {
            return f(VAULTBLOB_ERR_INVALID_SESSION, None);
        }
    };
    let vault = session.vault.clone();
    let vault_dir = session.vault_dir.clone();
    let vault_id = session.vault_id;
    let master_key = session.master_key.clone();
    drop(sessions);
    f(VAULTBLOB_OK, Some((vault, vault_dir, vault_id, master_key)))
}

// ---------------------------------------------------------------------------
// Input string parsing
// ---------------------------------------------------------------------------

fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, i32> {
    if ptr.is_null() {
        return Err(VAULTBLOB_ERR_INVALID_ARG);
    }
    unsafe {
        CStr::from_ptr(ptr)
            .to_str()
            .map_err(|_| VAULTBLOB_ERR_INVALID_ARG)
    }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_open(
    path: *const c_char,
    master_key: *const u8,
    max_chunk_size: u64,
    max_blob_size: u64,
    split_files: i32,
    stripe_chunks: i32,
) -> vaultblob_u64_result_t {
    let path_str = match cstr_to_str(path) {
        Ok(s) => s.to_owned(),
        Err(code) => return vaultblob_u64_result_t { code, value: 0 },
    };

    if master_key.is_null() {
        return vaultblob_u64_result_t {
            code: VAULTBLOB_ERR_INVALID_ARG,
            value: 0,
        };
    }

    let mk = unsafe {
        let mut bytes = [0u8; 32];
        std::ptr::copy_nonoverlapping(master_key, bytes.as_mut_ptr(), 32);
        VaultMasterKey(bytes)
    };

    let config = VaultConfig {
        max_chunk_size: max_chunk_size as usize,
        max_blob_size,
        split_files_across_blobs: split_files != 0,
        stripe_chunks_across_blobs: stripe_chunks != 0,
        cache_indexes_on_open: true,
    };

    let vault_path = PathBuf::from(&path_str);
    let vault = match vault_io::open_vault_from_dir_discover(&vault_path, &mk, config, false) {
        Ok(v) => v,
        Err(e) => {
            return vaultblob_u64_result_t {
                code: vault_error_code(&e),
                value: 0,
            };
        }
    };

    let vault_id = vault.vault_id();
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::SeqCst);

    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            return vaultblob_u64_result_t {
                code: VAULTBLOB_ERR_IO,
                value: 0,
            };
        }
    };
    sessions.insert(
        session_id,
        Session {
            vault: Arc::new(Mutex::new(SendVault(vault))),
            vault_dir: vault_path,
            vault_id,
            master_key: mk,
        },
    );

    vaultblob_u64_result_t {
        code: VAULTBLOB_OK,
        value: session_id,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_close(session_id: u64) -> vaultblob_result_t {
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return vaultblob_result_t { code: VAULTBLOB_ERR_IO },
    };
    sessions.remove(&session_id);
    vaultblob_result_t { code: VAULTBLOB_OK }
}

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_put_file(
    session_id: u64,
    data: *const u8,
    data_len: usize,
    file_id_hex: *const c_char,
) -> vaultblob_hex_result_t {
    let file_id = if file_id_hex.is_null() {
        vault_io::random_file_id()
    } else {
        match cstr_to_str(file_id_hex) {
            Ok(s) => match parse_file_id_from_str(s) {
                Ok(id) => id,
                Err(code) => {
                    return vaultblob_hex_result_t {
                        code,
                        value: [0u8; 37],
                    };
                }
            },
            Err(code) => {
                return vaultblob_hex_result_t {
                    code,
                    value: [0u8; 37],
                };
            }
        }
    };

    let data_slice = if data.is_null() && data_len == 0 {
        &[]
    } else if data.is_null() {
        return vaultblob_hex_result_t {
            code: VAULTBLOB_ERR_INVALID_ARG,
            value: [0u8; 37],
        };
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    };

    let hex = format_file_id_hex(file_id);

    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_hex_result_t { code, value: [0u8; 37] };
        }
        let (_vault_arc, vault_dir, vault_id, master_key) = opt.unwrap();
        let mut vault_guard = match _vault_arc.lock() {
            Ok(g) => g,
            Err(_) => {
                return vaultblob_hex_result_t {
                    code: VAULTBLOB_ERR_IO,
                    value: [0u8; 37],
                };
            }
        };

        match vault_io::put_file_with_retry(
            &mut vault_guard.0,
            &vault_dir,
            false,
            vault_id,
            &master_key,
            file_id,
            data_slice,
        ) {
            Ok(()) => vaultblob_hex_result_t {
                code: VAULTBLOB_OK,
                value: hex,
            },
            Err(e) => vaultblob_hex_result_t {
                code: vault_error_code(&e),
                value: [0u8; 37],
            },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_file_size(
    session_id: u64,
    file_id_hex: *const c_char,
) -> vaultblob_u64_result_t {
    let file_id = match cstr_to_str(file_id_hex) {
        Ok(s) => match parse_file_id_from_str(s) {
            Ok(id) => id,
            Err(code) => return vaultblob_u64_result_t { code, value: 0 },
        },
        Err(code) => return vaultblob_u64_result_t { code, value: 0 },
    };

    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_u64_result_t { code, value: 0 };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => return vaultblob_u64_result_t { code: VAULTBLOB_ERR_IO, value: 0 },
        };

        match vault_guard.0.file_size(file_id) {
            Ok(size) => vaultblob_u64_result_t {
                code: VAULTBLOB_OK,
                value: size,
            },
            Err(e) => vaultblob_u64_result_t {
                code: vault_error_code(&e),
                value: 0,
            },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_read_file(
    session_id: u64,
    file_id_hex: *const c_char,
    buffer: *mut u8,
    buffer_len: usize,
) -> vaultblob_u64_result_t {
    let file_id = match cstr_to_str(file_id_hex) {
        Ok(s) => match parse_file_id_from_str(s) {
            Ok(id) => id,
            Err(code) => return vaultblob_u64_result_t { code, value: 0 },
        },
        Err(code) => return vaultblob_u64_result_t { code, value: 0 },
    };

    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_u64_result_t { code, value: 0 };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let mut vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => return vaultblob_u64_result_t { code: VAULTBLOB_ERR_IO, value: 0 },
        };

        // Probe: if buffer is NULL or buffer_len == 0, return required size
        if buffer.is_null() || buffer_len == 0 {
            return match vault_guard.0.file_size(file_id) {
                Ok(size) => vaultblob_u64_result_t {
                    code: VAULTBLOB_ERR_BUF_TOO_SMALL,
                    value: size,
                },
                Err(e) => vaultblob_u64_result_t {
                    code: vault_error_code(&e),
                    value: 0,
                },
            };
        }

        match vault_guard.0.read_file(file_id) {
            Ok(data) => {
                if data.len() > buffer_len {
                    return vaultblob_u64_result_t {
                        code: VAULTBLOB_ERR_BUF_TOO_SMALL,
                        value: data.len() as u64,
                    };
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, data.len());
                }
                vaultblob_u64_result_t {
                    code: VAULTBLOB_OK,
                    value: data.len() as u64,
                }
            }
            Err(e) => vaultblob_u64_result_t {
                code: vault_error_code(&e),
                value: 0,
            },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_read_file_range(
    session_id: u64,
    file_id_hex: *const c_char,
    offset: u64,
    length: u64,
    buffer: *mut u8,
    buffer_len: usize,
) -> vaultblob_u64_result_t {
    let file_id = match cstr_to_str(file_id_hex) {
        Ok(s) => match parse_file_id_from_str(s) {
            Ok(id) => id,
            Err(code) => return vaultblob_u64_result_t { code, value: 0 },
        },
        Err(code) => return vaultblob_u64_result_t { code, value: 0 },
    };

    // Probe (no buffer): report what we would read
    if buffer.is_null() || buffer_len == 0 {
        return with_vault(session_id, |code, opt| {
            if code != VAULTBLOB_OK {
                return vaultblob_u64_result_t { code, value: 0 };
            }
            let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
            let vault_guard = match vault_arc.lock() {
                Ok(g) => g,
                Err(_) => {
                    return vaultblob_u64_result_t { code: VAULTBLOB_ERR_IO, value: 0 };
                }
            };

            match vault_guard.0.file_size(file_id) {
                Ok(size) => {
                    let available = size.saturating_sub(offset);
                    let wanted = if length == 0 { available } else { length.min(available) };
                    vaultblob_u64_result_t {
                        code: VAULTBLOB_ERR_BUF_TOO_SMALL,
                        value: wanted,
                    }
                }
                Err(e) => vaultblob_u64_result_t {
                    code: vault_error_code(&e),
                    value: 0,
                },
            }
        });
    }

    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_u64_result_t { code, value: 0 };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let mut vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => return vaultblob_u64_result_t { code: VAULTBLOB_ERR_IO, value: 0 },
        };

        match vault_guard.0.read_file_range(file_id, offset, length) {
            Ok(data) => {
                let to_copy = data.len().min(buffer_len);
                if to_copy > 0 {
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, to_copy);
                    }
                }
                vaultblob_u64_result_t {
                    code: VAULTBLOB_OK,
                    value: to_copy as u64,
                }
            }
            Err(e) => vaultblob_u64_result_t {
                code: vault_error_code(&e),
                value: 0,
            },
        }
    })
}

// ---------------------------------------------------------------------------
// Vault introspection
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_vault_id(session_id: u64) -> vaultblob_hex_result_t {
    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => {
            return vaultblob_hex_result_t {
                code: VAULTBLOB_ERR_IO,
                value: [0u8; 37],
            };
        }
    };
    let session = match sessions.get(&session_id) {
        Some(s) => s,
        None => {
            return vaultblob_hex_result_t {
                code: VAULTBLOB_ERR_INVALID_SESSION,
                value: [0u8; 37],
            };
        }
    };
    let hex = format_vault_id_hex(session.vault_id);
    vaultblob_hex_result_t {
        code: VAULTBLOB_OK,
        value: hex,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_blob_count(session_id: u64) -> vaultblob_size_result_t {
    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_size_result_t { code, value: 0 };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => return vaultblob_size_result_t { code: VAULTBLOB_ERR_IO, value: 0 },
        };
        let ids = vault_guard.0.blob_ids();
        vaultblob_size_result_t {
            code: VAULTBLOB_OK,
            value: ids.len(),
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_blob_id(
    session_id: u64,
    index: usize,
) -> vaultblob_hex_result_t {
    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_hex_result_t { code, value: [0u8; 37] };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => {
                return vaultblob_hex_result_t {
                    code: VAULTBLOB_ERR_IO,
                    value: [0u8; 37],
                };
            }
        };
        let ids = vault_guard.0.blob_ids();
        match ids.into_iter().nth(index) {
            Some(id) => vaultblob_hex_result_t {
                code: VAULTBLOB_OK,
                value: format_blob_id_hex(id),
            },
            None => vaultblob_hex_result_t {
                code: VAULTBLOB_ERR_BLOB_NOT_FOUND,
                value: [0u8; 37],
            },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_file_chunk_count(
    session_id: u64,
    file_id_hex: *const c_char,
) -> vaultblob_size_result_t {
    let file_id = match cstr_to_str(file_id_hex) {
        Ok(s) => match parse_file_id_from_str(s) {
            Ok(id) => id,
            Err(code) => return vaultblob_size_result_t { code, value: 0 },
        },
        Err(code) => return vaultblob_size_result_t { code, value: 0 },
    };

    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_size_result_t { code, value: 0 };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => return vaultblob_size_result_t { code: VAULTBLOB_ERR_IO, value: 0 },
        };

        match vault_guard.0.file_chunks(file_id) {
            Ok(chunks) => vaultblob_size_result_t {
                code: VAULTBLOB_OK,
                value: chunks.len(),
            },
            Err(e) => vaultblob_size_result_t {
                code: vault_error_code(&e),
                value: 0,
            },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_file_chunk(
    session_id: u64,
    file_id_hex: *const c_char,
    index: usize,
) -> vaultblob_chunk_info_result_t {
    let file_id = match cstr_to_str(file_id_hex) {
        Ok(s) => match parse_file_id_from_str(s) {
            Ok(id) => id,
            Err(code) => {
                return vaultblob_chunk_info_result_t {
                    code,
                    value: zeroed_chunk_info(),
                };
            }
        },
        Err(code) => {
            return vaultblob_chunk_info_result_t {
                code,
                value: zeroed_chunk_info(),
            };
        }
    };

    with_vault(session_id, |code, opt| {
        if code != VAULTBLOB_OK {
            return vaultblob_chunk_info_result_t {
                code,
                value: zeroed_chunk_info(),
            };
        }
        let (vault_arc, _dir, _vid, _mk) = opt.unwrap();
        let vault_guard = match vault_arc.lock() {
            Ok(g) => g,
            Err(_) => {
                return vaultblob_chunk_info_result_t {
                    code: VAULTBLOB_ERR_IO,
                    value: zeroed_chunk_info(),
                };
            }
        };

        match vault_guard.0.file_chunks(file_id) {
            Ok(chunks) => match chunks.get(index) {
                Some(chunk) => {
                    let info = vaultblob_chunk_info_t {
                        blob_id_hex: format_blob_id_hex(chunk.blob_id),
                        sequence_number: chunk.entry.sequence_number,
                        offset_in_blob: chunk.entry.offset_in_blob,
                        plaintext_length: chunk.entry.plaintext_length,
                        content_hash: chunk.entry.content_hash,
                    };
                    vaultblob_chunk_info_result_t {
                        code: VAULTBLOB_OK,
                        value: info,
                    }
                }
                None => vaultblob_chunk_info_result_t {
                    code: VAULTBLOB_ERR_FILE_NOT_FOUND,
                    value: zeroed_chunk_info(),
                },
            },
            Err(e) => vaultblob_chunk_info_result_t {
                code: vault_error_code(&e),
                value: zeroed_chunk_info(),
            },
        }
    })
}

fn zeroed_chunk_info() -> vaultblob_chunk_info_t {
    unsafe { std::mem::zeroed() }
}
