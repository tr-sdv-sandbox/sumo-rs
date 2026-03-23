//! Firmware encryption and compression.

use crate::error::OffboardError;
use crate::cose_key::CoseKey;
use crate::recipient::Recipient;

/// Encrypted payload: ciphertext + COSE_Encrypt info.
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub encryption_info: Vec<u8>,
}

/// Encrypt firmware with A128KW key wrapping.
pub fn encrypt_firmware(
    _plaintext: &[u8],
    _recipients: &[Recipient],
) -> Result<EncryptedPayload, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}

/// Encrypt firmware with ECDH-ES+A128KW key agreement.
pub fn encrypt_firmware_ecdh(
    _plaintext: &[u8],
    _sender_key: &CoseKey,
    _recipients: &[Recipient],
) -> Result<EncryptedPayload, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}

/// Compress firmware with zstd.
pub fn compress_firmware(_plaintext: &[u8], _level: i32) -> Result<Vec<u8>, OffboardError> {
    // TODO: Phase 6
    Err(OffboardError::Other("not implemented".into()))
}

/// Compute SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use suit_crypto::CryptoBackend;
    suit_crypto::RustCryptoBackend::new().sha256(data)
}
