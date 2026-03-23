//! SUIT envelope encoding to CBOR bytes.

use std::vec::Vec;

use crate::envelope::SuitEnvelope;
use crate::error::CodecError;

/// Encode a SUIT envelope to CBOR bytes.
///
/// The `sign_fn` callback receives the manifest CBOR bytes and must return
/// a COSE_Sign1 signature.
pub fn encode_envelope<F>(
    _envelope: &SuitEnvelope,
    _sign_fn: F,
) -> Result<Vec<u8>, CodecError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, CodecError>,
{
    // TODO: Phase 1 implementation
    Err(CodecError::CborEncode)
}
