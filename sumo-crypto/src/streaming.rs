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

/// Streaming AEAD encryptor — the mirror of [`StreamingAeadDecryptor`].
///
/// Emits ciphertext incrementally as plaintext is fed in, then yields the GCM
/// authentication tag on finalize. Appending `finalize()`'s tag to the
/// concatenated `update()` output forms a complete AES-GCM message, byte-for-byte
/// identical to a one-shot encrypt of the same plaintext — so the streaming
/// decryptor accepts it unchanged. Supports AAD = empty only (as does the
/// decryptor).
///
/// `Send`, so an offboard caller can hold one across `.await` points while
/// streaming an upload through an async runtime.
pub trait StreamingAeadEncryptor: Send {
    /// Encrypt a chunk of plaintext, writing ciphertext to `ciphertext` (which
    /// must be at least `plaintext.len()` bytes). Returns the number of
    /// ciphertext bytes written (always `plaintext.len()`).
    fn update(&mut self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<usize, CryptoError>;

    /// Finalize and return the 16-byte GCM authentication tag. Append it to the
    /// emitted ciphertext to complete the message.
    fn finalize(&mut self) -> Result<[u8; 16], CryptoError>;
}

/// Streaming hash computation.
pub trait StreamingHash {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> [u8; 32];
}
