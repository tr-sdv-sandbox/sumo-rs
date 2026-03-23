//! Key generation for signing and device keys.

use crate::cose_key::CoseKey;
use crate::error::OffboardError;

/// COSE algorithm identifiers.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;

/// Generate a signing keypair (ES256 or EdDSA).
pub fn generate_signing_key(_algorithm: i64) -> Result<CoseKey, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}

/// Generate a device key agreement keypair (P-256 ECDH or X25519).
pub fn generate_device_key(_algorithm: i64) -> Result<CoseKey, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}

/// Serialize a key as CBOR COSE_Key bytes.
pub fn serialize_key(_key: &CoseKey, _include_private: bool) -> Result<Vec<u8>, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}

/// Serialize a key as PEM string.
pub fn serialize_key_pem(_key: &CoseKey, _include_private: bool) -> Result<String, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}
