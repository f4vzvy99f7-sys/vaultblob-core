/// 32-byte vault master key provided by the application layer.
#[derive(Clone)]
pub struct VaultMasterKey(pub [u8; 32]);

/// UUID identifying a vault — same across all blobs in a vault.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VaultId(pub [u8; 16]);

/// UUID identifying a single blob file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlobId(pub [u8; 16]);

/// UUID identifying a logical file spread across one or more chunks.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FileId(pub [u8; 16]);

/// A decoded `0x02` index entry marking a complete logical file.
#[derive(Clone, Debug)]
pub struct FileCompleteEntry {
    pub file_id: FileId,
    pub total_chunks: u64,
    /// BLAKE2b-256 of the concatenated chunk plaintexts.
    pub full_content_hash: [u8; 32],
}

/// A decoded `0x01` index entry describing one chunk.
#[derive(Clone, Debug)]
pub struct ChunkEntry {
    pub file_id: FileId,
    pub sequence_number: u64,
    pub offset_in_blob: u64,
    pub plaintext_length: u64,
    /// BLAKE2b-256 of the chunk plaintext.
    pub content_hash: [u8; 32],
}
