//! Crypto error types.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    SignatureVerificationFailed,
    SigningFailed,
    InvalidKey,
    UnsupportedAlgorithm,
    KeyAgreementFailed,
    KeyUnwrapFailed,
    DecryptionFailed,
    EncryptionFailed,
    InvalidLength,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureVerificationFailed => write!(f, "signature verification failed"),
            Self::SigningFailed => write!(f, "signing failed"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
            Self::KeyAgreementFailed => write!(f, "key agreement failed"),
            Self::KeyUnwrapFailed => write!(f, "key unwrap failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::InvalidLength => write!(f, "invalid length"),
        }
    }
}

impl std::error::Error for CryptoError {}
