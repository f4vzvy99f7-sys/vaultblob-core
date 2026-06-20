use std::fs;
use std::path::{Path, PathBuf};

use rand::RngExt;
use vaultblob_core::{
    Blob, BlobConfig, FileId, Vault, VaultConfig, VaultError, VaultId, VaultMasterKey,
    discover_vault_id, generate_blob_filename,
};

pub fn blob_config(verbose: bool) -> BlobConfig {
    BlobConfig {
        initial_leading_gap: 128 * 1024,
        initial_trailing_gap: 128 * 1024,
        relocation_leading_padding: 2 * 1024 * 1024,
        relocation_trailing_padding: 512 * 1024,
        reader_retry_budget: 3,
        diagnostics: verbose,
    }
}

pub fn open_vault_from_dir(
    vault_dir: &Path,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    config: VaultConfig,
    verbose: bool,
) -> Result<Vault, VaultError> {
    let bcfg = blob_config(verbose);
    let blobs = collect_blobs(vault_dir, master_key, &bcfg)?;
    if blobs.is_empty() {
        let blob = create_blob(vault_dir, vault_id, master_key, &bcfg)?;
        return Vault::open(vault_id, vec![blob], config);
    }
    Vault::open(vault_id, blobs, config)
}

pub fn open_vault_from_dir_discover(
    vault_dir: &Path,
    master_key: &VaultMasterKey,
    config: VaultConfig,
    verbose: bool,
) -> Result<Vault, VaultError> {
    let bcfg = blob_config(verbose);
    let paths = collect_blob_paths(vault_dir, master_key)?;
    if paths.is_empty() {
        let vault_id: VaultId = VaultId(rand::random());
        let blob = create_blob(vault_dir, vault_id, master_key, &bcfg)?;
        return Vault::open(vault_id, vec![blob], config);
    }
    let vault_id = discover_vault_id(&paths[0], master_key)?;
    let blobs = collect_blobs(vault_dir, master_key, &bcfg)?;
    // Verify all blobs share the same vault_id
    for path in &paths {
        let vid = discover_vault_id(path, master_key)?;
        if vid != vault_id {
            return Err(VaultError::InvalidMasterKey);
        }
    }
    Vault::open(vault_id, blobs, config)
}

pub fn put_file_with_retry(
    vault: &mut Vault,
    vault_dir: &Path,
    verbose: bool,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    file_id: FileId,
    data: &[u8],
) -> Result<(), VaultError> {
    let bcfg = blob_config(verbose);
    loop {
        match vault.put_file(file_id, data) {
            Ok(()) => return Ok(()),
            Err(VaultError::NoWritableBlob) => {
                let blob = create_blob(vault_dir, vault_id, master_key, &bcfg)?;
                vault.append_blob(blob)?;
            }
            Err(err) => return Err(err),
        }
    }
}

fn collect_blob_paths(
    vault_dir: &Path,
    master_key: &VaultMasterKey,
) -> Result<Vec<PathBuf>, VaultError> {
    let mut paths: Vec<PathBuf> = fs::read_dir(vault_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if vaultblob_core::verify_blob_filename(master_key, name) {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    paths.sort();
    Ok(paths)
}

fn collect_blobs(
    vault_dir: &Path,
    master_key: &VaultMasterKey,
    blob_config: &BlobConfig,
) -> Result<Vec<Blob>, VaultError> {
    let paths = collect_blob_paths(vault_dir, master_key)?;
    paths
        .into_iter()
        .map(|path| Blob::open(&path, None, master_key, blob_config.clone()))
        .collect()
}

fn create_blob(
    vault_dir: &Path,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    blob_config: &BlobConfig,
) -> Result<Blob, VaultError> {
    let name = generate_blob_filename(master_key)?;
    let path = vault_dir.join(name);
    Blob::open(&path, Some(vault_id), master_key, blob_config.clone())
}

pub fn random_file_id() -> FileId {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    FileId(bytes)
}

pub fn format_file_id(file_id: FileId) -> String {
    let b = file_id.0;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    )
}

pub fn parse_file_id(s: &str) -> Result<FileId, VaultError> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return Err(VaultError::FileNotFound);
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| VaultError::FileNotFound)?;
    }
    Ok(FileId(bytes))
}
