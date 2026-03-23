//! Streaming zstd decompressor.

use crate::error::Sum2Error;

/// Streaming decompressor for zstd-compressed payloads.
pub struct StreamingDecompressor {
    _private: (),
}

impl StreamingDecompressor {
    /// Create a new streaming decompressor.
    pub fn new() -> Result<Self, Sum2Error> {
        // TODO: Phase 4
        Err(Sum2Error::Unsupported)
    }

    /// Decompress a chunk. Returns (bytes_consumed, bytes_produced).
    pub fn update(
        &mut self,
        _input: &[u8],
        _output: &mut [u8],
    ) -> Result<(usize, usize), Sum2Error> {
        // TODO: Phase 4
        Err(Sum2Error::Unsupported)
    }

    /// Finalize decompression.
    pub fn finalize(&mut self) -> Result<(), Sum2Error> {
        // TODO: Phase 4
        Err(Sum2Error::Unsupported)
    }
}
