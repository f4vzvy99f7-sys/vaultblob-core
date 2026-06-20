use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Mutex;

use vaultblob_core::{BlobId, Vault, VaultConfig, VaultError, VaultId, VaultMasterKey};

mod vault_io;

struct Session {
    vault_dir: PathBuf,
    vault: Mutex<Vault>,
    vault_id: VaultId,
    master_key: VaultMasterKey,
    verbose: bool,
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

fn to_vault_err(err: VaultError) -> String {
    format!("{err:?}")
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s)
        .unwrap_or_default()
        .into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_open_vault(
    path: *const c_char,
    master_key: *const u8,
    max_chunk_size: u64,
    max_blob_size: u64,
    split_files: i32,
    stripe_chunks: i32,
    verbose: i32,
    error_out: *mut *mut c_char,
) -> *mut Session {
    let path_str = match unsafe { cstr_to_str(path) } {
        Ok(s) => s.to_owned(),
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return std::ptr::null_mut();
        }
    };
    let verbose = verbose != 0;
    let path = PathBuf::from(&path_str);

    if master_key.is_null() {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string("master_key is null"); }
        }
        return std::ptr::null_mut();
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

    let vault = match vault_io::open_vault_from_dir_discover(&path, &mk, config, verbose) {
        Ok(v) => v,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return std::ptr::null_mut();
        }
    };

    let vault_id = vault.vault_id();

    Box::into_raw(Box::new(Session {
        vault_dir: path,
        vault: Mutex::new(vault),
        vault_id,
        master_key: mk,
        verbose,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_close(session: *mut Session) {
    if !session.is_null() {
        unsafe { drop(Box::from_raw(session)); }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_put_file(
    session: *mut Session,
    data: *const u8,
    data_len: usize,
    file_id: *const c_char,
    out_file_id: *mut *mut c_char,
    error_out: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string("null session"); }
        }
        return -1;
    }
    let session = unsafe { &*session };
    let data = unsafe { std::slice::from_raw_parts(data, data_len) };
    let file_id = if file_id.is_null() {
        vault_io::random_file_id()
    } else {
        let s = match unsafe { cstr_to_str(file_id) } {
            Ok(s) => s,
            Err(e) => {
                if !error_out.is_null() {
                    unsafe { *error_out = to_c_string(&to_vault_err(e)); }
                }
                return -1;
            }
        };
        match vault_io::parse_file_id(s) {
            Ok(id) => id,
            Err(e) => {
                if !error_out.is_null() {
                    unsafe { *error_out = to_c_string(&to_vault_err(e)); }
                }
                return -1;
            }
        }
    };

    let mut vault = match session.vault.lock() {
        Ok(g) => g,
        Err(_) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string("mutex poisoned"); }
            }
            return -1;
        }
    };

    if let Err(e) = vault_io::put_file_with_retry(
        &mut vault,
        &session.vault_dir,
        session.verbose,
        session.vault_id,
        &session.master_key,
        file_id,
        data,
    ) {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string(&to_vault_err(e)); }
        }
        return -1;
    }

    if !out_file_id.is_null() {
        unsafe { *out_file_id = to_c_string(&vault_io::format_file_id(file_id)); }
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_read_file(
    session: *mut Session,
    file_id: *const c_char,
    out_len: *mut usize,
    error_out: *mut *mut c_char,
) -> *mut u8 {
    if session.is_null() {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string("null session"); }
        }
        return std::ptr::null_mut();
    }
    let session = unsafe { &*session };
    let file_id_str = match unsafe { cstr_to_str(file_id) } {
        Ok(s) => s,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return std::ptr::null_mut();
        }
    };
    let file_id = match vault_io::parse_file_id(file_id_str) {
        Ok(id) => id,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return std::ptr::null_mut();
        }
    };

    let mut vault = match session.vault.lock() {
        Ok(g) => g,
        Err(_) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string("mutex poisoned"); }
            }
            return std::ptr::null_mut();
        }
    };

    match vault.read_file(file_id) {
        Ok(bytes) => {
            let boxed = bytes.into_boxed_slice();
            let len = boxed.len();
            let ptr = boxed.as_ptr() as *mut u8;
            std::mem::forget(boxed);
            if !out_len.is_null() {
                unsafe { *out_len = len; }
            }
            ptr
        }
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_read_file_range(
    session: *mut Session,
    file_id: *const c_char,
    offset: u64,
    length: u64,
    out_data: *mut *mut u8,
    out_len: *mut usize,
    error_out: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string("null session"); }
        }
        return -1;
    }
    let session = unsafe { &*session };
    let file_id_str = match unsafe { cstr_to_str(file_id) } {
        Ok(s) => s,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return -1;
        }
    };
    let file_id = match vault_io::parse_file_id(file_id_str) {
        Ok(id) => id,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return -1;
        }
    };

    let mut vault = match session.vault.lock() {
        Ok(g) => g,
        Err(_) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string("mutex poisoned"); }
            }
            return -1;
        }
    };

    match vault.read_file_range(file_id, offset, length) {
        Ok(bytes) => {
            let boxed = bytes.into_boxed_slice();
            let len = boxed.len();
            let ptr = boxed.as_ptr() as *mut u8;
            std::mem::forget(boxed);
            if !out_data.is_null() {
                unsafe { *out_data = ptr; }
            }
            if !out_len.is_null() {
                unsafe { *out_len = len; }
            }
            0
        }
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_file_size(
    session: *mut Session,
    file_id: *const c_char,
    out_size: *mut u64,
    error_out: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string("null session"); }
        }
        return -1;
    }
    let session = unsafe { &*session };
    let file_id_str = match unsafe { cstr_to_str(file_id) } {
        Ok(s) => s,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return -1;
        }
    };
    let file_id = match vault_io::parse_file_id(file_id_str) {
        Ok(id) => id,
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            return -1;
        }
    };

    let vault = match session.vault.lock() {
        Ok(g) => g,
        Err(_) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string("mutex poisoned"); }
            }
            return -1;
        }
    };

    match vault.file_size(file_id) {
        Ok(size) => {
            if !out_size.is_null() {
                unsafe { *out_size = size; }
            }
            0
        }
        Err(e) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string(&to_vault_err(e)); }
            }
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_blob_ids(
    session: *mut Session,
    out_ids: *mut *mut *mut c_char,
    out_count: *mut usize,
    error_out: *mut *mut c_char,
) -> i32 {
    if session.is_null() {
        if !error_out.is_null() {
            unsafe { *error_out = to_c_string("null session"); }
        }
        return -1;
    }
    let session = unsafe { &*session };

    let vault = match session.vault.lock() {
        Ok(g) => g,
        Err(_) => {
            if !error_out.is_null() {
                unsafe { *error_out = to_c_string("mutex poisoned"); }
            }
            return -1;
        }
    };

    let ids: Vec<String> = vault
        .blob_ids()
        .into_iter()
        .map(|id: BlobId| format_uuid(id.0))
        .collect();

    let count = ids.len();
    let mut arr: Vec<*mut c_char> = Vec::with_capacity(count);
    for id in ids {
        arr.push(to_c_string(&id));
    }

    let boxed = arr.into_boxed_slice();
    let ptr = boxed.as_ptr() as *mut *mut c_char;
    std::mem::forget(boxed);

    if !out_ids.is_null() {
        unsafe { *out_ids = ptr; }
    }
    if !out_count.is_null() {
        unsafe { *out_count = count; }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)); }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_free_string_array(arr: *mut *mut c_char, count: usize) {
    if !arr.is_null() {
        for i in 0..count {
            unsafe { vaultblob_free_string(*arr.add(i)); }
        }
        unsafe {
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(arr, count) as *mut [*mut c_char]);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn vaultblob_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len) as *mut [u8]);
        }
    }
}

unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, VaultError> {
    if ptr.is_null() {
        return Err(VaultError::InvalidConfig);
    }
    let slice = unsafe { CStr::from_ptr(ptr) };
    slice.to_str().map_err(|_| VaultError::InvalidConfig)
}
