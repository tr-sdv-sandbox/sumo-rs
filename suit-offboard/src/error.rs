//! Offboard error types.

use suit_codec::CodecError;
use suit_crypto::CryptoError;

/// Errors from offboard SUIT operations.
#[derive(Debug, thiserror::Error)]
pub enum OffboardError {
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
