pub mod blob;
pub mod crypto_utils;
pub mod diag;
pub mod error;
pub mod frontmatter;
pub mod types;
pub mod vault;

pub use blob::{
    AEAD_FRAME_OVERHEAD, Blob, BlobConfig, BlobIndex, BlobLayoutStats, INDEX_CHUNK_ENTRY_BYTES,
    INDEX_FILE_COMPLETE_ENTRY_BYTES, NewChunk, NewFileComplete, WriteChunksResult,
    estimate_index_bytes_for_file,
};
pub use error::VaultError;
pub use types::{BlobId, ChunkEntry, FileCompleteEntry, FileId, VaultId, VaultMasterKey};
pub use vault::{
    BlobWatchRegistrar, LocatedChunkEntry, LocatedFileCompleteEntry, Vault, VaultConfig,
    VaultFileCursor, VaultIndex,
};
