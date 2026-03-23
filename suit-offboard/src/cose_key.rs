//! COSE key management with import/export.

use crate::error::OffboardError;

/// A COSE key with optional private material.
pub struct CoseKey {
    inner: coset::CoseKey,
}

impl CoseKey {
    /// Import from DER-encoded key bytes.
    pub fn from_der(_der: &[u8]) -> Result<Self, OffboardError> {
        // TODO: Phase 6
        Err(OffboardError::Other("not implemented".into()))
    }

    /// Import from PEM-encoded key string.
    pub fn from_pem(_pem: &str) -> Result<Self, OffboardError> {
        // TODO: Phase 6
        Err(OffboardError::Other("not implemented".into()))
    }

    /// Import from CBOR-encoded COSE_Key bytes.
    pub fn from_cose_key_bytes(_cbor: &[u8]) -> Result<Self, OffboardError> {
        // TODO: Phase 6
        Err(OffboardError::Other("not implemented".into()))
    }

    /// Export the public key as CBOR COSE_Key bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        // TODO: Phase 6
        Vec::new()
    }

    /// Get the key identifier.
    pub fn key_id(&self) -> &[u8] {
        &self.inner.key_id
    }

    /// Access the inner coset key.
    pub(crate) fn inner(&self) -> &coset::CoseKey {
        &self.inner
    }
}
