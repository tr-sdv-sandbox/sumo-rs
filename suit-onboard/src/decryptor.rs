//! Streaming SUIT payload decryptor (AES-128-GCM).

use crate::error::Sum2Error;
use crate::manifest::Manifest;

/// Streaming decryptor for encrypted SUIT payloads.
pub struct StreamingDecryptor {
    _private: (),
}

impl StreamingDecryptor {
    /// Create a decryptor from a manifest's encryption info and a device key.
    pub fn new(
        _manifest: &Manifest,
        _component_index: usize,
        _device_key: &[u8],
    ) -> Result<Self, Sum2Error> {
        // TODO: Phase 4
        Err(Sum2Error::DecryptFailed)
    }

    /// Decrypt a chunk of ciphertext.
    pub fn update(&mut self, _ciphertext: &[u8], _plaintext: &mut [u8]) -> Result<usize, Sum2Error> {
        // TODO: Phase 4
        Err(Sum2Error::DecryptFailed)
    }

    /// Finalize decryption and verify the GCM tag.
    pub fn finalize(&mut self, _plaintext: &mut [u8]) -> Result<usize, Sum2Error> {
        // TODO: Phase 4
        Err(Sum2Error::DecryptFailed)
    }
}
