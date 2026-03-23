//! Device-side SUIT manifest validation, decryption, and orchestration.
//!
//! Provides the complete onboard update pipeline:
//! - Manifest validation with trust anchor verification
//! - Streaming AES-GCM decryption (ECDH-ES+A128KW or A128KW)
//! - Streaming zstd decompression
//! - Two-level manifest orchestration (campaign → image)
//! - Persistent policy (rollback protection)
//!
//! This crate is `no_std` compatible with the `alloc` feature.

// TODO: Add #![no_std] + extern crate alloc once dependency no_std support is verified

pub mod decryptor;
pub mod decompressor;
pub mod device_id;
pub mod error;
pub mod manifest;
pub mod orchestrator;
pub mod platform;
pub mod policy;
pub mod validator;

pub use error::Sum2Error;
pub use manifest::Manifest;
pub use platform::{PlatformOps, StorageOps};
pub use validator::Validator;
