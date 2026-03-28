//! Two-level manifest orchestration (campaign → image).

use crate::decryptor::StreamingDecryptor;
use crate::decompressor::StreamingDecompressor;
use crate::error::Sum2Error;
use crate::manifest::Manifest;
use crate::platform::PlatformOps;
use crate::validator::Validator;
use sumo_crypto::CryptoBackend;

const CHUNK_SIZE: usize = 4096;
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Process a single-image manifest: fetch, decrypt, decompress, verify, write.
pub fn process_image(
    validator: &Validator,
    manifest: &Manifest,
    ops: &dyn PlatformOps,
    crypto: &dyn CryptoBackend,
) -> Result<(), Sum2Error> {
    // Extract manifest parameters for component 0
    let comp_segments = manifest.component_id(0).ok_or(Sum2Error::InvalidEnvelope)?;
    let comp_id_bytes = encode_component_id(comp_segments);

    let uri = manifest.uri(0).ok_or(Sum2Error::InvalidEnvelope)?;
    let expected_digest = manifest.image_digest(0).ok_or(Sum2Error::InvalidEnvelope)?.0;

    // Fetch the payload
    let expected_size = manifest.image_size(0).unwrap_or(0) as usize;
    let alloc_size = if expected_size > 0 { expected_size + 1024 } else { 256 * 1024 };
    let mut fetch_buf = vec![0u8; alloc_size];
    let fetched = ops.fetch(uri, &mut fetch_buf)?;
    let payload = &fetch_buf[..fetched];

    // Check if payload is encrypted
    let has_encryption = manifest.encryption_info(0).is_some();

    let mut hasher = crypto.sha256_streaming();
    let mut write_offset: usize = 0;

    if has_encryption {
        // Get device key for decryption
        let device_keys = validator.device_keys();
        if device_keys.is_empty() {
            return Err(Sum2Error::DecryptFailed);
        }
        let device_key = &device_keys[0];

        let mut decryptor = StreamingDecryptor::new(manifest, 0, device_key, crypto)?;

        // Decrypt in chunks and detect compression
        let mut plaintext_buf = vec![0u8; CHUNK_SIZE + 256];
        let mut decompressor: Option<StreamingDecompressor> = None;
        let mut first_chunk = true;
        let mut pos = 0;

        while pos < payload.len() {
            let end = std::cmp::min(pos + CHUNK_SIZE, payload.len());
            let chunk = &payload[pos..end];
            pos = end;

            let pt_len = decryptor.update(chunk, &mut plaintext_buf)?;
            let pt = &plaintext_buf[..pt_len];

            if first_chunk && pt.len() >= 4 {
                if pt[..4] == ZSTD_MAGIC {
                    decompressor = Some(StreamingDecompressor::new()?);
                }
                first_chunk = false;
            }

            if let Some(ref mut dec) = decompressor {
                let mut _out = [0u8; 0];
                dec.update(pt, &mut _out)?;
            } else {
                hasher.update(pt);
                if !pt.is_empty() {
                    ops.write(&comp_id_bytes, write_offset, pt)?;
                    write_offset += pt.len();
                }
            }
        }

        // Finalize decryption (verify GCM tag)
        let final_len = decryptor.finalize(&mut plaintext_buf)?;
        if final_len > 0 {
            let pt = &plaintext_buf[..final_len];

            // Check for zstd magic if we haven't seen any decrypted data yet
            if first_chunk && pt.len() >= 4 {
                if pt[..4] == ZSTD_MAGIC {
                    decompressor = Some(StreamingDecompressor::new()?);
                }
            }

            if let Some(ref mut dec) = decompressor {
                let mut _out = [0u8; 0];
                dec.update(pt, &mut _out)?;
            } else {
                hasher.update(pt);
                ops.write(&comp_id_bytes, write_offset, pt)?;
                write_offset += pt.len();
            }
        }

        // Decompress if needed
        if let Some(mut dec) = decompressor {
            let decompressed = dec.finalize_to_vec()?;
            hasher.update(&decompressed);
            if !decompressed.is_empty() {
                ops.write(&comp_id_bytes, write_offset, &decompressed)?;
            }
        }
    } else {
        // Unencrypted payload — hash and write directly
        hasher.update(payload);
        ops.write(&comp_id_bytes, 0, payload)?;
    }

    // Verify digest
    let computed = hasher.finalize();
    if computed.as_slice() != expected_digest.bytes.as_slice() {
        return Err(Sum2Error::DigestMismatch);
    }

    // Persist sequence number
    ops.persist_sequence(&comp_id_bytes, manifest.sequence_number())?;

    Ok(())
}

/// Process a campaign manifest: iterate dependencies, fetch/validate L2 manifests,
/// then process each image.
pub fn process_campaign(
    validator: &Validator,
    manifest: &Manifest,
    ops: &dyn PlatformOps,
    crypto: &dyn CryptoBackend,
) -> Result<(), Sum2Error> {
    if !manifest.is_campaign() {
        return Err(Sum2Error::InvalidEnvelope);
    }

    let dep_count = manifest.dependency_count();
    for dep_idx in 0..dep_count {
        // Get URI for this dependency from dependency_resolution or install sequence
        let dep_uri = manifest.dependency_uri(dep_idx)
            .ok_or(Sum2Error::DependencyFailed)?;

        let l2_bytes = if dep_uri.starts_with('#') {
            // Integrated payload
            manifest.integrated_payload(dep_uri)
                .ok_or(Sum2Error::DependencyFailed)?
                .to_vec()
        } else {
            // Fetch external L2 manifest
            let mut buf = vec![0u8; 64 * 1024];
            let len = ops.fetch(dep_uri, &mut buf)?;
            buf.truncate(len);
            buf
        };

        // Validate the L2 manifest
        let l2_manifest = validator.validate_envelope(&l2_bytes, crypto, 0)?;

        // Process the L2 image
        process_image(validator, &l2_manifest, ops, crypto)?;
    }

    Ok(())
}

fn encode_component_id(segments: &[Vec<u8>]) -> Vec<u8> {
    // Simple concatenation with null separator for use as ops.write key
    let mut id = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            id.push(b'/');
        }
        id.extend_from_slice(seg);
    }
    id
}
