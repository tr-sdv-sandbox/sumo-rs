//! RustCrypto-based CryptoBackend implementation.

use std::boxed::Box;
use std::vec::Vec;

use crate::error::CryptoError;
use crate::streaming::{StreamingAeadDecryptor, StreamingHash};
use crate::traits::CryptoBackend;

/// CryptoBackend implementation using RustCrypto crates.
pub struct RustCryptoBackend;

impl RustCryptoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustCryptoBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoBackend for RustCryptoBackend {
    fn verify_sign1(
        &self,
        _key: &coset::CoseKey,
        _protected: &[u8],
        _payload: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn sign(
        &self,
        _key: &coset::CoseKey,
        _protected: &[u8],
        _payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn sha256_streaming(&self) -> Box<dyn StreamingHash> {
        Box::new(Sha256Stream(sha2::Sha256::new()))
    }

    fn ecdh_p256(
        &self,
        _private_key: &[u8],
        _peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn hkdf_sha256(
        &self,
        _ikm: &[u8],
        _salt: &[u8],
        _info: &[u8],
        _output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn aes_kw_unwrap(&self, _kek: &[u8], _wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn aes_kw_wrap(&self, _kek: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn aes_gcm_decrypt_stream(
        &self,
        _key: &[u8; 16],
        _iv: &[u8; 12],
        _aad: &[u8],
    ) -> Result<Box<dyn StreamingAeadDecryptor>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn aes_gcm_encrypt(
        &self,
        _key: &[u8; 16],
        _iv: &[u8; 12],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }

    fn random_bytes(&self, _buf: &mut [u8]) -> Result<(), CryptoError> {
        // TODO: Phase 2
        Err(CryptoError::UnsupportedAlgorithm)
    }
}

use sha2::Digest;

struct Sha256Stream(sha2::Sha256);

impl StreamingHash for Sha256Stream {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self: Box<Self>) -> [u8; 32] {
        self.0.finalize().into()
    }
}
