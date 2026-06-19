use crate::crypto_utils::EncryptedContainer;
use crate::frontmatter::FrontMatter;

pub struct Blob {
    // contains three segments: frontmatter, data, index in that order with padding between data and index or on the end
    frontmatter: EncryptedContainer<FrontMatter>,

    data_blocks: DatBlocks,

    Index:
}
