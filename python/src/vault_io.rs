//! On-disk vault directory helpers for Python.
//!
//! Mirrors the CLI's vault-dir workflow but only calls the public `vaultblob-core` API.
//! This module is private to the Python crate — not part of the core library.

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngExt;
use vaultblob_core::{
    Blob, BlobConfig, FileId, Vault, VaultConfig, VaultError, VaultId, VaultMasterKey,
};

const META_FILENAME: &str = "vault.meta";

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

pub fn open_or_create_meta(
    vault_dir: &Path,
    password: &str,
) -> Result<(VaultId, VaultMasterKey), VaultError> {
    let meta_path = vault_dir.join(META_FILENAME);
    if meta_path.exists() {
        load_meta(vault_dir, password)
    } else {
        fs::create_dir_all(vault_dir)?;
        let mut vault_id_bytes = [0u8; 16];
        let mut salt = [0u8; 32];
        rand::rng().fill(&mut vault_id_bytes);
        rand::rng().fill(&mut salt);

        let mut meta = [0u8; 48];
        meta[..16].copy_from_slice(&vault_id_bytes);
        meta[16..].copy_from_slice(&salt);
        fs::write(&meta_path, meta)?;

        let vault_id = VaultId(vault_id_bytes);
        let master_key = derive_master_key(password, &salt)?;
        Ok((vault_id, master_key))
    }
}

pub fn load_meta(vault_dir: &Path, password: &str) -> Result<(VaultId, VaultMasterKey), VaultError> {
    let data = fs::read(vault_dir.join(META_FILENAME))?;
    if data.len() != 48 {
        return Err(VaultError::IndexChainBroken);
    }
    let vault_id = VaultId(data[..16].try_into().unwrap());
    let salt: [u8; 32] = data[16..].try_into().unwrap();
    Ok((vault_id, derive_master_key(password, &salt)?))
}

fn derive_master_key(password: &str, salt: &[u8; 32]) -> Result<VaultMasterKey, VaultError> {
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| VaultError::InvalidMasterKey)?;
    Ok(VaultMasterKey(key))
}

pub fn open_vault_from_dir(
    vault_dir: &Path,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    config: VaultConfig,
    verbose: bool,
) -> Result<Vault, VaultError> {
    let bcfg = blob_config(verbose);
    let blobs = collect_blobs(vault_dir, vault_id, master_key, &bcfg)?;
    if blobs.is_empty() {
        let blob = create_blob(vault_dir, vault_id, master_key, &bcfg)?;
        return Vault::open(vault_id, vec![blob], config);
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

fn collect_blobs(
    vault_dir: &Path,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    blob_config: &BlobConfig,
) -> Result<Vec<Blob>, VaultError> {
    let mut paths: Vec<PathBuf> = fs::read_dir(vault_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if name.starts_with("blob-") && name.ends_with(".blob") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| Blob::open(&path, vault_id, master_key, blob_config.clone()))
        .collect()
}

fn create_blob(
    vault_dir: &Path,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    blob_config: &BlobConfig,
) -> Result<Blob, VaultError> {
    let mut n = 1usize;
    loop {
        let path = vault_dir.join(format!("blob-{n:04}.blob"));
        if !path.exists() {
            return Blob::open(&path, vault_id, master_key, blob_config.clone());
        }
        n += 1;
    }
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
