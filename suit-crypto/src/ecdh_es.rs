//! ECDH-ES+A128KW key agreement and key wrapping.

use std::vec::Vec;

use crate::error::CryptoError;
use crate::traits::CryptoBackend;

/// Perform ECDH-ES+A128KW key unwrapping.
///
/// 1. ECDH between device private key and ephemeral public key
/// 2. Derive KEK via HKDF-SHA256 with COSE_KDF_Context
/// 3. AES-KW unwrap CEK
pub fn ecdh_es_a128kw_unwrap(
    _crypto: &dyn CryptoBackend,
    _device_private_key: &[u8],
    _ephemeral_public_key: &[u8],
    _wrapped_cek: &[u8],
    _protected: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // TODO: Phase 2 implementation
    Err(CryptoError::KeyUnwrapFailed)
}

/// Perform ECDH-ES+A128KW key wrapping (for encryption).
pub fn ecdh_es_a128kw_wrap(
    _crypto: &dyn CryptoBackend,
    _sender_private_key: &[u8],
    _recipient_public_key: &[u8],
    _cek: &[u8],
    _protected: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // TODO: Phase 2 implementation — returns (wrapped_cek, ephemeral_public_key)
    Err(CryptoError::KeyAgreementFailed)
}
