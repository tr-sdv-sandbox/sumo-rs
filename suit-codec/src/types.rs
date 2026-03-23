//! Core SUIT types: Uuid, SemVer, DigestInfo, VersionMatch.

use std::string::String;
use std::vec::Vec;

/// RFC 4122 UUID (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Uuid(pub [u8; 16]);

/// Semantic version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub prerelease: Option<String>,
    pub build: Option<String>,
}

/// Digest algorithm identifiers (COSE algorithm values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum DigestAlgorithm {
    Sha256 = -16,
    Sha384 = -43,
    Sha512 = -44,
}

/// A digest: algorithm + hash bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestInfo {
    pub algorithm: DigestAlgorithm,
    pub bytes: Vec<u8>,
}

/// Version comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VersionComparison {
    Greater = 1,
    GreaterEqual = 2,
    Equal = 3,
    LesserEqual = 4,
    Lesser = 5,
}

/// Version match condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMatch {
    pub comparison: VersionComparison,
    pub parts: Vec<i64>,
}
