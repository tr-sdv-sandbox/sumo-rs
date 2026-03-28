//! SUIT manifest types and CBOR codec.
//!
//! Implements encoding and decoding of SUIT envelopes (RFC 9124)
//! using ciborium for CBOR and coset for COSE structures.
//!
//! This crate is `no_std` compatible with the `alloc` feature.

// TODO: Add #![no_std] + extern crate alloc once ciborium no_std support is verified

pub mod commands;
pub mod component;
pub mod decode;
pub mod encode;
pub mod envelope;
pub mod error;
pub mod labels;
pub mod manifest;
pub mod parameters;
pub mod text;
pub mod types;

pub use envelope::SuitEnvelope;
pub use error::CodecError;
pub use manifest::SuitManifest;
pub use types::{DigestAlgorithm, DigestInfo, SemVer, Uuid, VersionComparison, VersionMatch};
