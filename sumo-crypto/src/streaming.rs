//! Streaming crypto traits for chunked operations.

use crate::error::CryptoError;

/// Streaming AEAD decryptor that buffers trailing bytes as potential GCM tag.
pub trait StreamingAeadDecryptor {
    /// Process a chunk of ciphertext, writing plaintext to output.
    /// Returns the number of plaintext bytes written.
    fn update(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<usize, CryptoError>;

    /// Finalize decryption and verify the GCM authentication tag.
    /// Returns any remaining plaintext bytes.
    fn finalize(&mut self, plaintext: &mut [u8]) -> Result<usize, CryptoError>;
}

/// Streaming hash computation.
pub trait StreamingHash {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> [u8; 32];
}
