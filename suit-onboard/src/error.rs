//! Onboard error types matching the C API.

use std::fmt;

/// Error codes for onboard SUIT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Sum2Error {
    InvalidEnvelope = -1,
    AuthFailed = -2,
    VendorMismatch = -3,
    ClassMismatch = -4,
    DeviceMismatch = -5,
    RollbackRejected = -6,
    Revoked = -7,
    Expired = -8,
    DependencyFailed = -9,
    DigestMismatch = -10,
    DecryptFailed = -11,
    OutOfMemory = -12,
    Unsupported = -13,
    CallbackFailed = -14,
    DelegationFailed = -15,
}

impl fmt::Display for Sum2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope => write!(f, "invalid envelope"),
            Self::AuthFailed => write!(f, "authentication failed"),
            Self::VendorMismatch => write!(f, "vendor mismatch"),
            Self::ClassMismatch => write!(f, "class mismatch"),
            Self::DeviceMismatch => write!(f, "device mismatch"),
            Self::RollbackRejected => write!(f, "rollback rejected"),
            Self::Revoked => write!(f, "key revoked"),
            Self::Expired => write!(f, "manifest expired"),
            Self::DependencyFailed => write!(f, "dependency failed"),
            Self::DigestMismatch => write!(f, "digest mismatch"),
            Self::DecryptFailed => write!(f, "decryption failed"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::Unsupported => write!(f, "unsupported feature"),
            Self::CallbackFailed => write!(f, "callback failed"),
            Self::DelegationFailed => write!(f, "delegation failed"),
        }
    }
}
