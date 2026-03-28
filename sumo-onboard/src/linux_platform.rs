//! Linux platform HAL implementing PlatformOps and StorageOps.
//!
//! - `fetch`: supports `file://` and filesystem paths
//! - `write`: writes firmware to files under a staging directory
//! - `persist_sequence` / storage: uses a JSON file for key-value persistence

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::error::Sum2Error;
use crate::platform::{PlatformOps, StorageOps};

/// Linux filesystem-based platform implementation.
pub struct LinuxPlatformOps {
    /// Directory where fetched URIs are mapped to local files.
    fetch_root: PathBuf,
    /// Directory where firmware is staged during updates.
    staging_dir: PathBuf,
    /// Directory for persisted sequence numbers.
    state_dir: PathBuf,
}

impl LinuxPlatformOps {
    /// Create a new Linux platform with the given directories.
    ///
    /// - `fetch_root`: base directory for resolving relative file:// URIs
    /// - `staging_dir`: where firmware images are written during update
    /// - `state_dir`: where sequence numbers are persisted
    pub fn new(fetch_root: PathBuf, staging_dir: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            fetch_root,
            staging_dir,
            state_dir,
        }
    }

    fn resolve_uri(&self, uri: &str) -> PathBuf {
        if let Some(path) = uri.strip_prefix("file://") {
            PathBuf::from(path)
        } else if uri.starts_with('/') {
            PathBuf::from(uri)
        } else {
            self.fetch_root.join(uri)
        }
    }

    fn component_path(&self, component_id: &[u8]) -> PathBuf {
        let name = String::from_utf8_lossy(component_id).replace('/', "_");
        self.staging_dir.join(name)
    }

    fn seq_path(&self, component_id: &[u8]) -> PathBuf {
        let name = String::from_utf8_lossy(component_id).replace('/', "_");
        self.state_dir.join(format!("{name}.seq"))
    }
}

impl PlatformOps for LinuxPlatformOps {
    fn fetch(&self, uri: &str, buf: &mut [u8]) -> Result<usize, Sum2Error> {
        let path = self.resolve_uri(uri);
        let data = fs::read(&path).map_err(|_| Sum2Error::CallbackFailed)?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    fn write(&self, component_id: &[u8], offset: usize, data: &[u8]) -> Result<(), Sum2Error> {
        use std::io::{Seek, SeekFrom, Write};

        let path = self.component_path(component_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| Sum2Error::CallbackFailed)?;
        }

        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| Sum2Error::CallbackFailed)?;

        file.seek(SeekFrom::Start(offset as u64))
            .map_err(|_| Sum2Error::CallbackFailed)?;
        file.write_all(data)
            .map_err(|_| Sum2Error::CallbackFailed)?;

        Ok(())
    }

    fn invoke(&self, _component_id: &[u8]) -> Result<(), Sum2Error> {
        // On Linux, invoke is a no-op (caller handles boot)
        Ok(())
    }

    fn swap(&self, _comp_a: &[u8], _comp_b: &[u8]) -> Result<(), Sum2Error> {
        // A/B swap not implemented for generic Linux
        Err(Sum2Error::Unsupported)
    }

    fn persist_sequence(&self, component_id: &[u8], seq: u64) -> Result<(), Sum2Error> {
        let path = self.seq_path(component_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|_| Sum2Error::CallbackFailed)?;
        }
        fs::write(&path, seq.to_string().as_bytes())
            .map_err(|_| Sum2Error::CallbackFailed)
    }
}

/// Linux filesystem-based persistent storage for policy state.
pub struct LinuxStorageOps {
    path: PathBuf,
}

impl LinuxStorageOps {
    /// Create storage backed by a JSON file at the given path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load(&self) -> HashMap<String, String> {
        let content = match fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(_) => return HashMap::new(),
        };
        let mut map = HashMap::new();
        for line in content.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
        map
    }

    fn save(&self, map: &HashMap<String, String>) -> Result<(), Sum2Error> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|_| Sum2Error::CallbackFailed)?;
        }
        let content: String = map
            .iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect();
        fs::write(&self.path, content).map_err(|_| Sum2Error::CallbackFailed)
    }
}

impl StorageOps for LinuxStorageOps {
    fn read_u64(&self, key: &str) -> Result<u64, Sum2Error> {
        self.load()
            .get(key)
            .and_then(|v| v.parse().ok())
            .ok_or(Sum2Error::CallbackFailed)
    }

    fn write_u64(&self, key: &str, value: u64) -> Result<(), Sum2Error> {
        let mut map = self.load();
        map.insert(key.to_string(), value.to_string());
        self.save(&map)
    }

    fn read_i64(&self, key: &str) -> Result<i64, Sum2Error> {
        self.load()
            .get(key)
            .and_then(|v| v.parse().ok())
            .ok_or(Sum2Error::CallbackFailed)
    }

    fn write_i64(&self, key: &str, value: i64) -> Result<(), Sum2Error> {
        let mut map = self.load();
        map.insert(key.to_string(), value.to_string());
        self.save(&map)
    }
}
