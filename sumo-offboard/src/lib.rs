//! Server-side SUIT manifest building, signing, and encryption.
//!
//! Provides:
//! - Key generation (ES256, EdDSA) and serialization (CBOR, PEM)
//! - Image manifest builder (L2 single-ECU updates)
//! - Campaign builder (L1 multi-ECU orchestration)
//! - Firmware encryption (A128KW, ECDH-ES+A128KW) and compression (zstd)

pub mod campaign_builder;
pub mod cose_key;
pub mod encryptor;
pub mod error;
pub mod image_builder;
pub mod keygen;
pub mod recipient;

pub use campaign_builder::CampaignBuilder;
pub use cose_key::CoseKey;
pub use error::OffboardError;
pub use image_builder::ImageManifestBuilder;
pub use keygen::{generate_device_key, generate_signing_key};
