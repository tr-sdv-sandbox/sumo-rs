//! Crypto traits and RustCrypto backend for SUIT operations.
//!
//! Provides abstract `CryptoBackend` trait and a default implementation
//! using the RustCrypto ecosystem (p256, ed25519-dalek, aes-gcm, etc.).
//!
//! This crate is `no_std` compatible with the `alloc` feature.

// TODO: Add #![no_std] + extern crate alloc once dependency no_std support is verified

pub mod cose_key;
pub mod ecdh_es;
pub mod error;
pub mod rustcrypto;
pub mod streaming;
pub mod traits;

pub use error::CryptoError;
pub use rustcrypto::RustCryptoBackend;
pub use traits::CryptoBackend;
