struct VolatileSlot {
    generation: u64,
    index_offset: u64,
    index_length: u64,
    index_mac: [u8; 32],
}

pub struct FrontMatter {
    vault_id: uuid::Uuid,
    blob_id: uuid::Uuid,
    wrapped_K_data: [u8; 32],
    wrapped_K_index: [u8; 32],

    // always stays up to date with
    volatile1: VolatileSlot,
    volatile2: VolatileSlot,
}
