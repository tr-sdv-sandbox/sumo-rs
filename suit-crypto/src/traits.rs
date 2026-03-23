//! Abstract crypto backend trait.

use std::boxed::Box;
use std::vec::Vec;

use crate::error::CryptoError;
use crate::streaming::{StreamingAeadDecryptor, StreamingHash};

/// Abstract cryptographic backend.
///
/// Implementations provide signature verification, signing, hashing,
/// key agreement, key wrapping, and AEAD encryption/decryption.
pub trait CryptoBackend {
    fn verify_sign1(
        &self,
        key: &coset::CoseKey,
        protected: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    fn sign(
        &self,
        key: &coset::CoseKey,
        protected: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn sha256(&self, data: &[u8]) -> [u8; 32];

    fn sha256_streaming(&self) -> Box<dyn StreamingHash>;

    fn ecdh_p256(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError>;

    fn aes_kw_unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn aes_kw_wrap(&self, kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;

    fn aes_gcm_decrypt_stream(
        &self,
        key: &[u8; 16],
        iv: &[u8; 12],
        aad: &[u8],
    ) -> Result<Box<dyn StreamingAeadDecryptor>, CryptoError>;

    fn aes_gcm_encrypt(
        &self,
        key: &[u8; 16],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CryptoError>;
}
