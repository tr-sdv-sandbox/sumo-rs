//! Codec error types.

use std::fmt;

/// Errors from SUIT envelope encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// CBOR parsing failed.
    CborDecode,
    /// Missing required field in manifest.
    MissingField(&'static str),
    /// Invalid value for a field.
    InvalidValue(&'static str),
    /// Unsupported manifest version.
    UnsupportedVersion(u32),
    /// CBOR encoding failed.
    CborEncode,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CborDecode => write!(f, "CBOR decode error"),
            Self::MissingField(name) => write!(f, "missing field: {name}"),
            Self::InvalidValue(name) => write!(f, "invalid value: {name}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported manifest version: {v}"),
            Self::CborEncode => write!(f, "CBOR encode error"),
        }
    }
}

impl std::error::Error for CodecError {}
