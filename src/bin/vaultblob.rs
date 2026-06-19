use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand::RngExt;
use vaultblob_core::{Blob, BlobConfig, FileId, Vault, VaultConfig, VaultError, VaultId, VaultMasterKey};

const META_FILENAME: &str = "vault.meta";

fn blob_config(verbose: bool) -> BlobConfig {
    BlobConfig {
        initial_leading_gap: 128 * 1024,
        initial_trailing_gap: 128 * 1024,
        relocation_leading_padding: 2 * 1024 * 1024,
        relocation_trailing_padding: 512 * 1024,
        reader_retry_budget: 3,
        diagnostics: verbose,
    }
}

#[derive(Parser)]
#[command(name = "vaultblob", about = "Store and retrieve files in an encrypted vault")]
struct Cli {
    /// Path to the vault directory
    vault_dir: PathBuf,

    /// Log index walks and locator selection to stderr (also set VAULTBLOB_DEBUG=1)
    #[arg(long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write files into the vault and print their file IDs
    Put {
        /// Maximum plaintext per chunk (e.g. 4mb, 512kb, 8192)
        #[arg(long, default_value = "4mb", value_parser = parse_byte_size_usize)]
        max_chunk_size: usize,

        /// Soft max estimated data bytes per blob before starting another (e.g. 10mb, 1gb)
        #[arg(long, default_value = "1gb", value_parser = parse_byte_size)]
        max_blob_size: u64,

        /// Allow a single file's chunks to span multiple blobs
        #[arg(long)]
        split: bool,

        /// When splitting, rotate chunk placement across blobs round-robin
        #[arg(long)]
        stripe: bool,

        /// Files or glob patterns to ingest; omit to read from stdin
        files: Vec<String>,
    },

    /// Read a file from the vault and write it to stdout
    Get {
        /// File ID printed by a prior `put`
        file_id: String,
    },

    /// Print per-blob layout breakdown (gaps, data, index) for debugging
    Stat,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Put {
            max_chunk_size,
            max_blob_size,
            split,
            stripe,
            files,
        } => cmd_put(
            &cli.vault_dir,
            cli.verbose,
            max_chunk_size,
            max_blob_size,
            split,
            stripe,
            files,
        ),
        Command::Get { file_id } => cmd_get(&cli.vault_dir, cli.verbose, &file_id),
        Command::Stat => cmd_stat(&cli.vault_dir, cli.verbose),
    }
}

fn cmd_put(
    vault_dir: &Path,
    verbose: bool,
    max_chunk_size: usize,
    max_blob_size: u64,
    split: bool,
    stripe: bool,
    file_patterns: Vec<String>,
) -> Result<()> {
    let password = prompt_password()?;
    let (vault_id, master_key) = open_or_create_meta(vault_dir, &password)?;

    let config = VaultConfig {
        max_chunk_size,
        max_blob_size,
        split_files_across_blobs: split,
        stripe_chunks_across_blobs: stripe,
        cache_indexes_on_open: true,
    };

    let mut vault = open_vault(vault_dir, verbose, vault_id, &master_key, config)?;

    if file_patterns.is_empty() {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data).context("reading stdin")?;
        let file_id = random_file_id();
        put_file_with_retry(
            &mut vault,
            vault_dir,
            verbose,
            vault_id,
            &master_key,
            file_id,
            &data,
        )
        .context("writing stdin to vault")?;
        println!("{}", format_id(file_id));
    } else {
        let paths = expand_patterns(&file_patterns)?;
        for path in paths {
            let data = fs::read(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let file_id = random_file_id();
            put_file_with_retry(
                &mut vault,
                vault_dir,
                verbose,
                vault_id,
                &master_key,
                file_id,
                &data,
            )
            .with_context(|| format!("writing {} to vault", path.display()))?;
            println!("{}\t{}", format_id(file_id), path.display());
        }
    }

    Ok(())
}

fn cmd_get(vault_dir: &Path, verbose: bool, file_id_str: &str) -> Result<()> {
    let password = prompt_password()?;
    let (vault_id, master_key) = load_meta(vault_dir, &password)?;

    let mut vault = open_vault(
        vault_dir,
        verbose,
        vault_id,
        &master_key,
        VaultConfig::default(),
    )?;
    let file_id = parse_file_id(file_id_str)?;
    let data = vault.read_file(file_id).map_err(|e| match e {
        VaultError::FileNotFound => anyhow::anyhow!("file not found: {file_id_str}"),
        VaultError::FileHashMismatch => anyhow::anyhow!("file integrity check failed"),
        VaultError::InvalidMasterKey => anyhow::anyhow!("wrong password"),
        other => anyhow::anyhow!("vault error: {other:?}"),
    })?;

    io::stdout().write_all(&data).context("writing to stdout")?;
    Ok(())
}

fn cmd_stat(vault_dir: &Path, verbose: bool) -> Result<()> {
    let password = prompt_password()?;
    let (vault_id, master_key) = load_meta(vault_dir, &password)?;

    let mut vault = open_vault(
        vault_dir,
        verbose,
        vault_id,
        &master_key,
        VaultConfig::default(),
    )?;

    for (path, stats) in vault
        .layout_stats()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .into_iter()
        .map(|(_id, path, stats)| (path, stats))
    {
        println!("=== {} ===", path.display());
        print!("{stats}");
    }
    Ok(())
}

/// Attempt put_file; on NoWritableBlob, create a new blob, attach it, and retry.
fn put_file_with_retry(
    vault: &mut Vault,
    vault_dir: &Path,
    verbose: bool,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    file_id: FileId,
    data: &[u8],
) -> Result<()> {
    loop {
        match vault.put_file(file_id, data) {
            Ok(()) => return Ok(()),
            Err(VaultError::NoWritableBlob) => {
                let blob = create_blob(vault_dir, verbose, vault_id, master_key)
                    .context("creating new blob after capacity exhausted")?;
                vault
                    .append_blob(blob)
                    .map_err(|e| anyhow::anyhow!("attaching new blob: {e:?}"))?;
            }
            Err(VaultError::InvalidMasterKey) => bail!("wrong password"),
            Err(VaultError::FileExceedsBlobCapacity) => bail!(
                "file is larger than --max-blob-size; raise the limit or pass --split to span blobs"
            ),
            Err(e) => bail!("vault error: {e:?}"),
        }
    }
}

fn parse_byte_size(s: &str) -> Result<u64, String> {
    parse_byte_size_inner(s).map_err(|err| err.to_string())
}

fn parse_byte_size_usize(s: &str) -> Result<usize, String> {
    let bytes = parse_byte_size(s)?;
    usize::try_from(bytes).map_err(|_| format!("size too large for this platform: {s}"))
}

fn parse_byte_size_inner(s: &str) -> Result<u64> {
    let s = s.trim().replace('_', "");
    if s.is_empty() {
        bail!("size must not be empty");
    }

    let split = s
        .char_indices()
        .find(|(_, ch)| !ch.is_ascii_digit())
        .map(|(index, _)| index)
        .unwrap_or(s.len());
    let (number, suffix) = s.split_at(split);
    if number.is_empty() {
        bail!("size must start with a number (examples: 4096, 4mb, 512kb)");
    }

    let value: u64 = number
        .parse()
        .with_context(|| format!("invalid size number in {s:?}"))?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" | "byte" | "bytes" => 1,
        "k" | "kb" | "kib" | "ki" => 1024,
        "m" | "mb" | "mib" | "mi" => 1024_u64.pow(2),
        "g" | "gb" | "gib" | "gi" => 1024_u64.pow(3),
        "t" | "tb" | "tib" | "ti" => 1024_u64.pow(4),
        other => bail!("unknown size suffix {other:?} (use b, kb, mb, or gb)"),
    };

    value
        .checked_mul(multiplier)
        .with_context(|| format!("size overflow parsing {s:?}"))
}

fn prompt_password() -> Result<String> {
    rpassword::prompt_password("Vault password: ").context("reading password")
}

fn open_or_create_meta(vault_dir: &Path, password: &str) -> Result<(VaultId, VaultMasterKey)> {
    let meta_path = vault_dir.join(META_FILENAME);
    if meta_path.exists() {
        read_meta(&meta_path, password)
    } else {
        fs::create_dir_all(vault_dir).context("creating vault directory")?;
        let mut vault_id_bytes = [0u8; 16];
        let mut salt = [0u8; 32];
        rand::rng().fill(&mut vault_id_bytes);
        rand::rng().fill(&mut salt);

        let mut meta = [0u8; 48];
        meta[..16].copy_from_slice(&vault_id_bytes);
        meta[16..].copy_from_slice(&salt);
        fs::write(&meta_path, meta).context("writing vault metadata")?;

        let vault_id = VaultId(vault_id_bytes);
        let master_key = derive_key(password, &salt)?;
        Ok((vault_id, master_key))
    }
}

fn load_meta(vault_dir: &Path, password: &str) -> Result<(VaultId, VaultMasterKey)> {
    read_meta(&vault_dir.join(META_FILENAME), password)
}

fn read_meta(meta_path: &Path, password: &str) -> Result<(VaultId, VaultMasterKey)> {
    let data = fs::read(meta_path).context("reading vault metadata")?;
    if data.len() != 48 {
        bail!("corrupt vault metadata (unexpected length)");
    }
    let vault_id = VaultId(data[..16].try_into().unwrap());
    let salt: [u8; 32] = data[16..].try_into().unwrap();
    let master_key = derive_key(password, &salt)?;
    Ok((vault_id, master_key))
}

fn derive_key(password: &str, salt: &[u8; 32]) -> Result<VaultMasterKey> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(VaultMasterKey(key))
}

fn open_vault(
    vault_dir: &Path,
    verbose: bool,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
    config: VaultConfig,
) -> Result<Vault> {
    let blobs = collect_blobs(vault_dir, verbose, vault_id, master_key)?;
    if blobs.is_empty() {
        let blob = create_blob(vault_dir, verbose, vault_id, master_key)?;
        return Vault::open(vault_id, vec![blob], config)
            .map_err(|e| anyhow::anyhow!("opening vault: {e:?}"));
    }
    Vault::open(vault_id, blobs, config).map_err(|e| anyhow::anyhow!("opening vault: {e:?}"))
}

fn collect_blobs(
    vault_dir: &Path,
    verbose: bool,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
) -> Result<Vec<Blob>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(vault_dir)
        .context("reading vault directory")?
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

    let mut blobs = Vec::with_capacity(paths.len());
    for path in paths {
        let blob = Blob::open(&path, vault_id, master_key, blob_config(verbose))
            .map_err(|e| anyhow::anyhow!("opening {}: {e:?}", path.display()))?;
        blobs.push(blob);
    }
    Ok(blobs)
}

fn create_blob(
    vault_dir: &Path,
    verbose: bool,
    vault_id: VaultId,
    master_key: &VaultMasterKey,
) -> Result<Blob> {
    let mut n = 1usize;
    loop {
        let path = vault_dir.join(format!("blob-{n:04}.blob"));
        if !path.exists() {
            return Blob::open(&path, vault_id, master_key, blob_config(verbose))
                .map_err(|e| anyhow::anyhow!("creating {}: {e:?}", path.display()));
        }
        n += 1;
    }
}

fn expand_patterns(patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for pattern in patterns {
        let pattern = expand_tilde(pattern);
        let matches: Vec<PathBuf> = glob::glob(&pattern)
            .with_context(|| format!("invalid glob pattern: {pattern}"))?
            .collect::<Result<Vec<_>, _>>()
            .context("expanding glob pattern")?;
        if matches.is_empty() {
            bail!("no files matched: {pattern}");
        }
        paths.extend(matches.into_iter().filter(|p| p.is_file()));
    }
    Ok(paths)
}

fn expand_tilde(pattern: &str) -> String {
    if pattern == "~" {
        return std::env::var("HOME").unwrap_or_else(|_| pattern.to_string());
    }
    if let Some(rest) = pattern.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    pattern.to_string()
}

fn random_file_id() -> FileId {
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    FileId(bytes)
}

fn format_id(file_id: FileId) -> String {
    let b = file_id.0;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3],
        b[4], b[5],
        b[6], b[7],
        b[8], b[9],
        b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

fn parse_file_id(s: &str) -> Result<FileId> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        bail!("invalid file ID (expected 32 hex chars, optionally UUID-formatted): {s}");
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex in file ID: {s}"))?;
    }
    Ok(FileId(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_human_byte_sizes() {
        assert_eq!(parse_byte_size("4096").unwrap(), 4096);
        assert_eq!(parse_byte_size("5kb").unwrap(), 5 * 1024);
        assert_eq!(parse_byte_size("10MB").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_byte_size("1 gb").unwrap(), 1024_u64.pow(3));
        assert_eq!(parse_byte_size_usize("512k").unwrap(), 512 * 1024);
    }
}
