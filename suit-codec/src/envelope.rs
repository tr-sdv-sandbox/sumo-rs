//! SUIT envelope: authentication wrapper + manifest + integrated payloads.

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use crate::manifest::SuitManifest;
use crate::types::DigestInfo;

/// Authentication block containing digest and signatures.
#[derive(Debug, Clone)]
pub struct SuitAuthentication {
    pub digest: DigestInfo,
    pub signatures: Vec<Vec<u8>>, // raw COSE_Sign1 bytes
}

/// A complete SUIT envelope.
#[derive(Debug, Clone)]
pub struct SuitEnvelope {
    pub authentication: SuitAuthentication,
    pub manifest: SuitManifest,
    /// Integrated payloads keyed by URI fragment (e.g., "#firmware").
    pub integrated_payloads: BTreeMap<String, Vec<u8>>,
    /// Raw manifest bytes (for signature verification).
    pub manifest_bytes: Vec<u8>,
}
