use std::io;

#[derive(Debug)]
pub enum VaultError {
    Io(io::Error),
    AeadDecryptFailed,
    AeadEncryptFailed,
    IndexChainBroken,
    TailHashMismatch,
    IndexMacMismatch,
    NoValidLocator,
    InvalidMasterKey,
    InvalidConfig,
    InvalidChunkSize,
    FileNotFound,
    IncompleteFile,
    FileAlreadyExists,
    FileHashMismatch,
    BlobNotFound,
    NoWritableBlob,
    /// A single write exceeds `max_blob_size` and cannot be split across blobs.
    FileExceedsBlobCapacity,
    IntegerOverflow,
    UnsupportedPlatform,
    RetryBudgetExceeded,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        VaultError::Io(e)
    }
}
