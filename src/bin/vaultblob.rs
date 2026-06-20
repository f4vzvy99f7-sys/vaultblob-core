use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand::RngExt;
use vaultblob_core::{
    Blob, BlobConfig, FileId, Vault, VaultConfig, VaultError, VaultId, VaultMasterKey,
    verify_blob_filename, generate_blob_filename, discover_vault_id,
};

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

    /// Master key as 64 hex characters (also via VAULTBLOB_MASTER_KEY env var)
    #[arg(long, default_value_t = String::new())]
    master_key: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write files into the vault and print their file IDs
    Put {
        #[arg(long, default_value = "4mb", value_parser = parse_byte_size_usize)]
        max_chunk_size: usize,

        #[arg(long, default_value = "1gb", value_parser = parse_byte_size)]
        max_blob_size: u64,

        #[arg(long)]
        split: bool,

        #[arg(long)]
        stripe: bool,

        files: Vec<String>,
    },

    /// Read a file from the vault and write it to stdout
    Get {
        file_id: String,
    },

    /// Print per-blob layout breakdown for debugging
    Stat,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let key_hex = if !cli.master_key.is_empty() {
        cli.master_key.clone()
    } else if let Ok(v) = std::env::var("VAULTBLOB_MASTER_KEY") {
        v
    } else {
        eprint!("Master key (64 hex chars): ");
        let mut line = String::new();
        io::stdin().read_line(&mut line).context("reading master key")?;
        line.trim().to_owned()
    };
    let master_key = parse_master_key(&key_hex)?;

    match cli.command {
        Command::Put {
            max_chunk_size,
            max_blob_size,
            split,
            stripe,
            files,
        } => cmd_put(
            &cli.vault_dir, &master_key,
            max_chunk_size, max_blob_size, split, stripe, files,
        ),
        Command::Get { file_id } => cmd_get(&cli.vault_dir, &master_key, &file_id),
        Command::Stat => cmd_stat(&cli.vault_dir, &master_key),
    }
}

fn parse_master_key(s: &str) -> Result<VaultMasterKey> {
    let s = s.trim();
    if s.len() != 64 {
        bail!("master key must be 64 hex characters (32 bytes)");
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(s, &mut bytes).context("invalid master key hex")?;
    Ok(VaultMasterKey(bytes))
}

fn collect_blob_paths(vault_dir: &Path, master_key: &VaultMasterKey) -> Result<Vec<PathBuf>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(vault_dir)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if verify_blob_filename(master_key, name) {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    paths.sort();
    Ok(paths)
}

fn open_vault_from_dir(
    vault_dir: &Path,
    master_key: &VaultMasterKey,
    config: VaultConfig,
) -> Result<Vault> {
    let bcfg = blob_config(false);
    let paths = collect_blob_paths(vault_dir, master_key)?;

    if paths.is_empty() {
        let vault_id = VaultId(rand::random());
        let name = generate_blob_filename(master_key)?;
        let blob = Blob::open(&vault_dir.join(name), Some(vault_id), master_key, bcfg)?;
        return Vault::open(vault_id, vec![blob], config)
            .map_err(|e| anyhow::anyhow!("opening new vault: {e:?}"));
    }

    let vault_id = discover_vault_id(&paths[0], master_key)?;
    let mut blobs = Vec::with_capacity(paths.len());
    for path in &paths {
        let blob = Blob::open_existing(path, Some(vault_id), master_key, bcfg.clone())?;
        blobs.push(blob);
    }
    Vault::open(vault_id, blobs, config)
        .map_err(|e| anyhow::anyhow!("opening vault: {e:?}"))
}

fn put_file_with_retry(
    vault: &mut Vault,
    vault_dir: &Path,
    master_key: &VaultMasterKey,
    file_id: FileId,
    data: &[u8],
) -> Result<()> {
    let bcfg = blob_config(false);
    loop {
        match vault.put_file(file_id, data) {
            Ok(()) => return Ok(()),
            Err(VaultError::NoWritableBlob) => {
                let vault_id = vault.vault_id();
                let name = generate_blob_filename(master_key)?;
                let blob = Blob::open(&vault_dir.join(name), Some(vault_id), master_key, bcfg.clone())?;
                vault.append_blob(blob)
                    .map_err(|e| anyhow::anyhow!("attaching new blob: {e:?}"))?;
            }
            Err(VaultError::FileExceedsBlobCapacity) => bail!(
                "file is larger than --max-blob-size; raise the limit or pass --split"
            ),
            Err(e) => bail!("vault error: {e:?}"),
        }
    }
}

fn cmd_put(
    vault_dir: &Path,
    master_key: &VaultMasterKey,
    max_chunk_size: usize,
    max_blob_size: u64,
    split: bool,
    stripe: bool,
    file_patterns: Vec<String>,
) -> Result<()> {
    let config = VaultConfig {
        max_chunk_size,
        max_blob_size,
        split_files_across_blobs: split,
        stripe_chunks_across_blobs: stripe,
        cache_indexes_on_open: true,
    };

    let mut vault = open_vault_from_dir(vault_dir, master_key, config)?;

    if file_patterns.is_empty() {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data).context("reading stdin")?;
        let file_id = FileId(rand::random());
        put_file_with_retry(&mut vault, vault_dir, master_key, file_id, &data)
            .context("writing stdin to vault")?;
        println!("{}", format_file_id(file_id));
    } else {
        let paths = expand_patterns(&file_patterns)?;
        for path in paths {
            let data = fs::read(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let file_id = FileId(rand::random());
            put_file_with_retry(&mut vault, vault_dir, master_key, file_id, &data)
                .with_context(|| format!("writing {} to vault", path.display()))?;
            println!("{}\t{}", format_file_id(file_id), path.display());
        }
    }
    Ok(())
}

fn cmd_get(vault_dir: &Path, master_key: &VaultMasterKey, file_id_str: &str) -> Result<()> {
    let mut vault = open_vault_from_dir(vault_dir, master_key, VaultConfig::default())?;
    let file_id = parse_file_id(file_id_str)?;
    let data = vault.read_file(file_id).map_err(|e| match e {
        VaultError::FileNotFound => anyhow::anyhow!("file not found: {file_id_str}"),
        VaultError::FileHashMismatch => anyhow::anyhow!("file integrity check failed"),
        VaultError::InvalidMasterKey => anyhow::anyhow!("wrong master key"),
        other => anyhow::anyhow!("vault error: {other:?}"),
    })?;
    io::stdout().write_all(&data).context("writing to stdout")?;
    Ok(())
}

fn cmd_stat(vault_dir: &Path, master_key: &VaultMasterKey) -> Result<()> {
    let mut vault = open_vault_from_dir(vault_dir, master_key, VaultConfig::default())?;
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

fn format_file_id(file_id: FileId) -> String {
    let b = file_id.0;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    )
}

fn parse_file_id(s: &str) -> Result<FileId> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        bail!("invalid file id: expected 32 hex digits, got {}", hex.len());
    }
    let mut bytes = [0u8; 16];
    hex::decode_to_slice(&hex, &mut bytes).context("invalid file id hex")?;
    Ok(FileId(bytes))
}

fn expand_patterns(patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for pattern in patterns {
        for entry in glob::glob(pattern).context("invalid glob pattern")? {
            paths.push(entry.context("reading glob entry")?);
        }
    }
    paths.sort();
    Ok(paths)
}
