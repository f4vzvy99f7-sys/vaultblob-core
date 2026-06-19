use std::fmt::Display;
use std::path::Path;
use std::time::Instant;

use crate::types::BlobId;

pub fn diagnostics_enabled(config_diagnostics: bool) -> bool {
    config_diagnostics || std::env::var_os("VAULTBLOB_DEBUG").is_some()
}

pub fn log_line(blob_path: &Path, blob_id: BlobId, enabled: bool, msg: impl Display) {
    if !enabled {
        return;
    }
    eprintln!(
        "[vaultblob:{} blob={}] {}",
        blob_path.display(),
        format_blob_id(blob_id),
        msg
    );
}

pub fn elapsed(start: Instant) -> std::time::Duration {
    start.elapsed()
}

fn format_blob_id(blob_id: BlobId) -> String {
    let b = &blob_id.0;
    format!(
        "{:02x}{:02x}{:02x}{:02x}…",
        b[0], b[1], b[2], b[3]
    )
}

pub fn format_locator(
    slot_index: u8,
    generation: u64,
    index_offset: u64,
    index_length: u64,
) -> String {
    format!(
        "slot={slot_index} generation={generation} index_offset={index_offset} index_length={index_length}"
    )
}

pub fn format_vault_error(err: &crate::error::VaultError) -> &'static str {
    match err {
        crate::error::VaultError::Io(_) => "Io",
        crate::error::VaultError::AeadDecryptFailed => "AeadDecryptFailed",
        crate::error::VaultError::AeadEncryptFailed => "AeadEncryptFailed",
        crate::error::VaultError::IndexChainBroken => "IndexChainBroken",
        crate::error::VaultError::TailHashMismatch => "TailHashMismatch",
        crate::error::VaultError::IndexMacMismatch => "IndexMacMismatch",
        crate::error::VaultError::NoValidLocator => "NoValidLocator",
        crate::error::VaultError::InvalidMasterKey => "InvalidMasterKey",
        crate::error::VaultError::InvalidConfig => "InvalidConfig",
        crate::error::VaultError::InvalidChunkSize => "InvalidChunkSize",
        crate::error::VaultError::FileNotFound => "FileNotFound",
        crate::error::VaultError::IncompleteFile => "IncompleteFile",
        crate::error::VaultError::FileAlreadyExists => "FileAlreadyExists",
        crate::error::VaultError::FileHashMismatch => "FileHashMismatch",
        crate::error::VaultError::BlobNotFound => "BlobNotFound",
        crate::error::VaultError::NoWritableBlob => "NoWritableBlob",
        crate::error::VaultError::FileExceedsBlobCapacity => "FileExceedsBlobCapacity",
        crate::error::VaultError::IntegerOverflow => "IntegerOverflow",
        crate::error::VaultError::UnsupportedPlatform => "UnsupportedPlatform",
        crate::error::VaultError::RetryBudgetExceeded => "RetryBudgetExceeded",
    }
}
