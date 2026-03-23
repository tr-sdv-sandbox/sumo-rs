//! Platform abstraction traits for device I/O and storage.

use crate::error::Sum2Error;

/// Platform I/O operations — the device provides this implementation.
pub trait PlatformOps {
    /// Fetch data from a URI into a buffer. Returns bytes fetched.
    fn fetch(&self, uri: &str, buf: &mut [u8]) -> Result<usize, Sum2Error>;

    /// Write decrypted firmware to component storage at the given offset.
    fn write(&self, component_id: &[u8], offset: usize, data: &[u8]) -> Result<(), Sum2Error>;

    /// Invoke (boot) a component after successful update.
    fn invoke(&self, component_id: &[u8]) -> Result<(), Sum2Error>;

    /// Swap two components atomically (A/B partition switch).
    fn swap(&self, comp_a: &[u8], comp_b: &[u8]) -> Result<(), Sum2Error>;

    /// Persist the accepted sequence number for rollback protection.
    fn persist_sequence(&self, component_id: &[u8], seq: u64) -> Result<(), Sum2Error>;
}

/// Persistent key-value storage for policy state.
pub trait StorageOps {
    fn read_u64(&self, key: &str) -> Result<u64, Sum2Error>;
    fn write_u64(&self, key: &str, value: u64) -> Result<(), Sum2Error>;
    fn read_i64(&self, key: &str) -> Result<i64, Sum2Error>;
    fn write_i64(&self, key: &str, value: i64) -> Result<(), Sum2Error>;
}
