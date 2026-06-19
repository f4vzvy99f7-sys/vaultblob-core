mod vault_io;

use std::path::PathBuf;
use std::sync::Mutex;

use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use vaultblob_core::{Vault, VaultConfig, VaultError, VaultId, VaultMasterKey};

use vault_io::{
    format_file_id, load_meta, open_or_create_meta, open_vault_from_dir, parse_file_id,
    put_file_with_retry, random_file_id,
};

create_exception!(_native, VaultBlobError, pyo3::exceptions::PyException);

/// Python handle to an on-disk vault. Wraps `vaultblob_core::Vault` plus session state.
#[pyclass(unsendable)]
struct VaultSession {
    vault_dir: PathBuf,
    vault_id: VaultId,
    master_key: VaultMasterKey,
    verbose: bool,
    vault: Mutex<Vault>,
}

#[pymethods]
impl VaultSession {
    #[staticmethod]
    #[pyo3(signature = (path, password, *, max_chunk_size=None, max_blob_size=None, split=false, stripe=false, verbose=false))]
    fn open(
        path: PathBuf,
        password: &str,
        max_chunk_size: Option<usize>,
        max_blob_size: Option<u64>,
        split: bool,
        stripe: bool,
        verbose: bool,
    ) -> PyResult<Self> {
        let (vault_id, master_key) = open_or_create_meta(&path, password).map_err(to_py_err)?;
        let config = VaultConfig {
            max_chunk_size: max_chunk_size.unwrap_or(4 * 1024 * 1024),
            max_blob_size: max_blob_size.unwrap_or(1024 * 1024 * 1024),
            split_files_across_blobs: split,
            stripe_chunks_across_blobs: stripe,
            cache_indexes_on_open: true,
        };
        let vault = open_vault_from_dir(&path, vault_id, &master_key, config, verbose)
            .map_err(to_py_err)?;
        Ok(Self {
            vault_dir: path,
            vault_id,
            master_key,
            verbose,
            vault: Mutex::new(vault),
        })
    }

    #[staticmethod]
    #[pyo3(signature = (path, password, *, verbose=false))]
    fn open_existing(path: PathBuf, password: &str, verbose: bool) -> PyResult<Self> {
        let (vault_id, master_key) = load_meta(&path, password).map_err(to_py_err)?;
        let vault = open_vault_from_dir(
            &path,
            vault_id,
            &master_key,
            VaultConfig::default(),
            verbose,
        )
        .map_err(to_py_err)?;
        Ok(Self {
            vault_dir: path,
            vault_id,
            master_key,
            verbose,
            vault: Mutex::new(vault),
        })
    }

    #[getter]
    fn vault_id(&self) -> String {
        format_uuid(self.vault_id.0)
    }

    fn blob_ids(&self) -> PyResult<Vec<String>> {
        let vault = self.vault.lock().map_err(|_| to_py_err(VaultError::InvalidConfig))?;
        Ok(vault
            .blob_ids()
            .into_iter()
            .map(|id| format_uuid(id.0))
            .collect())
    }

    #[pyo3(signature = (data, *, file_id=None))]
    fn put_file(&self, data: &[u8], file_id: Option<&str>) -> PyResult<String> {
        let file_id = match file_id {
            Some(s) => parse_file_id(s).map_err(to_py_err)?,
            None => random_file_id(),
        };
        let mut vault = self.vault.lock().map_err(|_| to_py_err(VaultError::InvalidConfig))?;
        put_file_with_retry(
            &mut vault,
            &self.vault_dir,
            self.verbose,
            self.vault_id,
            &self.master_key,
            file_id,
            data,
        )
        .map_err(to_py_err)?;
        Ok(format_file_id(file_id))
    }

    fn read_file<'py>(&self, py: Python<'py>, file_id: &str) -> PyResult<Bound<'py, PyBytes>> {
        let file_id = parse_file_id(file_id).map_err(to_py_err)?;
        let mut vault = self.vault.lock().map_err(|_| to_py_err(VaultError::InvalidConfig))?;
        let data = vault.read_file(file_id).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    /// Per-blob layout breakdown as `(path, report_text)` pairs.
    fn layout_stats(&self) -> PyResult<Vec<(String, String)>> {
        let mut vault = self.vault.lock().map_err(|_| to_py_err(VaultError::InvalidConfig))?;
        vault
            .layout_stats()
            .map_err(to_py_err)?
            .into_iter()
            .map(|(_blob_id, path, stats)| {
                Ok((path.display().to_string(), format!("{stats}")))
            })
            .collect()
    }

    fn __repr__(&self) -> String {
        format!(
            "VaultSession(path={:?}, vault_id={})",
            self.vault_dir,
            format_uuid(self.vault_id.0)
        )
    }
}

fn format_uuid(bytes: [u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

fn to_py_err(err: VaultError) -> PyErr {
    VaultBlobError::new_err(format!("{err:?}"))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VaultSession>()?;
    m.add("VaultBlobError", m.py().get_type::<VaultBlobError>())?;
    Ok(())
}
