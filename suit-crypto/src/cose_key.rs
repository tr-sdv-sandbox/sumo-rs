//! COSE_Key parsing and construction helpers.

use crate::error::CryptoError;

/// Parse a COSE_Key from CBOR bytes into a `coset::CoseKey`.
pub fn parse_cose_key(_cbor: &[u8]) -> Result<coset::CoseKey, CryptoError> {
    // TODO: Phase 2 implementation
    Err(CryptoError::InvalidKey)
}
