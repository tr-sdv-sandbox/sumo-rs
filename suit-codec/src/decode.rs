//! SUIT envelope decoding from CBOR bytes.

use std::vec::Vec;

use crate::envelope::SuitEnvelope;
use crate::error::CodecError;

/// Decode a SUIT envelope from CBOR bytes.
pub fn decode_envelope(_data: &[u8]) -> Result<SuitEnvelope, CodecError> {
    // TODO: Phase 1 implementation
    Err(CodecError::CborDecode)
}

/// Decode raw CBOR bytes into a manifest, without authentication.
pub fn decode_manifest_only(_data: &[u8]) -> Result<SuitEnvelope, CodecError> {
    // TODO: Phase 1 implementation
    Err(CodecError::CborDecode)
}

/// Extract the raw manifest bytes from an envelope for signature verification.
pub fn extract_manifest_bytes(_envelope_data: &[u8]) -> Result<Vec<u8>, CodecError> {
    // TODO: Phase 1 implementation
    Err(CodecError::CborDecode)
}
