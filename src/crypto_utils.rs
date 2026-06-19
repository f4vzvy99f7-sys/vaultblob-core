pub struct EncryptedContainer<T> {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    cached_data: Option<Box<T>>,
    tag: [u8; 16],
}
