//! Streaming zstd decompressor.
//!
//! Wraps ruzstd (pure-Rust zstd implementation) for no_std-compatible
//! streaming decompression of SUIT firmware payloads.

use crate::error::Sum2Error;

/// Streaming decompressor for zstd-compressed payloads.
pub struct StreamingDecompressor {
    /// Accumulated compressed input (ruzstd processes complete frames).
    input_buf: Vec<u8>,
}

impl StreamingDecompressor {
    /// Create a new streaming decompressor.
    pub fn new() -> Result<Self, Sum2Error> {
        Ok(Self {
            input_buf: Vec::new(),
        })
    }

    /// Feed compressed data. Accumulates internally since ruzstd
    /// processes complete frames. Returns (bytes_consumed, bytes_produced).
    ///
    /// Note: All output is produced at finalize_to_vec() time.
    pub fn update(
        &mut self,
        input: &[u8],
        _output: &mut [u8],
    ) -> Result<(usize, usize), Sum2Error> {
        self.input_buf.extend_from_slice(input);
        Ok((input.len(), 0))
    }

    /// Decompress all accumulated input and return as a Vec.
    pub fn finalize_to_vec(&mut self) -> Result<Vec<u8>, Sum2Error> {
        use ruzstd::io::Read;
        let mut decoder = ruzstd::StreamingDecoder::new(self.input_buf.as_slice())
            .map_err(|_| Sum2Error::Unsupported)?;
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match decoder.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => output.extend_from_slice(&buf[..n]),
                Err(_) => return Err(Sum2Error::Unsupported),
            }
        }
        self.input_buf.clear();
        Ok(output)
    }

    /// Finalize decompression (validation only).
    pub fn finalize(&mut self) -> Result<(), Sum2Error> {
        if self.input_buf.is_empty() {
            return Ok(());
        }
        let _ = self.finalize_to_vec()?;
        Ok(())
    }
}
