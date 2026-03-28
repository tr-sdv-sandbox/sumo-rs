//! SUIT command parameters.

use std::string::String;
use std::vec::Vec;

use crate::types::{DigestInfo, Uuid, VersionMatch};

/// A single SUIT parameter (label + value).
#[derive(Debug, Clone)]
pub struct SuitParameter {
    pub label: i64,
    pub value: ParameterValue,
}

/// Parameter value variants.
#[derive(Debug, Clone)]
pub enum ParameterValue {
    ImageDigest(DigestInfo),
    ImageSize(u64),
    Uri(String),
    VendorId(Uuid),
    ClassId(Uuid),
    DeviceId(Uuid),
    EncryptionInfo(Vec<u8>),
    Version(VersionMatch),
    Raw(Vec<u8>),
}
