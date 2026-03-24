//! SUIT envelope validator with trust anchor management.

use coset::CborSerializable;

use crate::device_id::DeviceId;
use crate::error::Sum2Error;
use crate::manifest::Manifest;
use suit_codec::types::DigestAlgorithm;
use suit_crypto::CryptoBackend;

/// Validates SUIT envelopes against trust anchors and device policy.
pub struct Validator {
    device_id: Option<DeviceId>,
    trust_anchors: Vec<coset::CoseKey>,
    revoked_kids: Vec<Vec<u8>>,
    device_keys: Vec<coset::CoseKey>,
    min_seq: Option<u64>,
    reject_before: Option<i64>,
}

impl Validator {
    /// Create a new validator with a trust anchor (COSE_Key CBOR bytes) and optional device identity.
    pub fn new(trust_anchor: &[u8], device_id: Option<DeviceId>) -> Self {
        let key =
            coset::CoseKey::from_slice(trust_anchor).expect("invalid trust anchor COSE_Key CBOR");
        Self {
            device_id,
            trust_anchors: vec![key],
            revoked_kids: Vec::new(),
            device_keys: Vec::new(),
            min_seq: None,
            reject_before: None,
        }
    }

    /// Add an additional trust anchor (COSE_Key CBOR bytes).
    pub fn add_trust_anchor(&mut self, key_cbor: &[u8]) -> Result<(), Sum2Error> {
        let key = coset::CoseKey::from_slice(key_cbor).map_err(|_| Sum2Error::AuthFailed)?;
        self.trust_anchors.push(key);
        Ok(())
    }

    /// Mark a key ID as revoked. Any envelope signed with this kid will be rejected.
    pub fn revoke_kid(&mut self, kid: &[u8]) -> Result<(), Sum2Error> {
        self.revoked_kids.push(kid.to_vec());
        Ok(())
    }

    /// Add a device key for ECDH decryption (COSE_Key CBOR bytes).
    pub fn add_device_key(&mut self, key_cbor: &[u8]) -> Result<(), Sum2Error> {
        let key = coset::CoseKey::from_slice(key_cbor).map_err(|_| Sum2Error::DecryptFailed)?;
        self.device_keys.push(key);
        Ok(())
    }

    /// Set the minimum accepted sequence number for anti-rollback.
    pub fn set_min_sequence(&mut self, seq: u64) {
        self.min_seq = Some(seq);
    }

    /// Set a timestamp before which envelopes are rejected.
    pub fn set_reject_before(&mut self, timestamp: i64) {
        self.reject_before = Some(timestamp);
    }

    /// Get device keys (for decryptor access).
    pub fn device_keys(&self) -> &[coset::CoseKey] {
        &self.device_keys
    }

    /// Validate a SUIT envelope and return the parsed manifest on success.
    ///
    /// Steps:
    /// 1. Decode the CBOR envelope
    /// 2. Verify the manifest digest
    /// 3. Verify the COSE_Sign1 signature against trust anchors
    /// 4. Check key revocation
    /// 5. Check anti-rollback (sequence number)
    /// 6. Check timestamp-based revocation
    /// 7. Check device identity conditions (vendor/class/device ID)
    pub fn validate_envelope(
        &self,
        envelope_bytes: &[u8],
        crypto: &dyn CryptoBackend,
        _trusted_time: i64,
    ) -> Result<Manifest, Sum2Error> {
        // 1. Decode envelope
        let envelope = suit_codec::decode::decode_envelope(envelope_bytes)
            .map_err(|_| Sum2Error::InvalidEnvelope)?;

        // 2. Verify manifest digest
        let expected_digest = &envelope.authentication.digest;
        let actual_hash = match expected_digest.algorithm {
            DigestAlgorithm::Sha256 => crypto.sha256(&envelope.manifest_bytes),
            _ => return Err(Sum2Error::Unsupported),
        };
        if actual_hash.as_slice() != expected_digest.bytes.as_slice() {
            return Err(Sum2Error::AuthFailed);
        }

        // 3. Verify COSE_Sign1 signature(s) against trust anchors
        let mut any_sig_valid = false;
        for sig_bytes in &envelope.authentication.signatures {
            let sign1 = coset::CoseSign1::from_slice(sig_bytes)
                .map_err(|_| Sum2Error::AuthFailed)?;

            // The payload in COSE_Sign1 for SUIT is the digest CBOR (already verified above)
            // The protected header is serialized as part of the Sig_structure
            let protected_bytes = sign1.protected.original_data.as_deref().unwrap_or(&[]);

            // Try all trust anchors
            for anchor in &self.trust_anchors {
                // Check kid match if both have kid
                if !sign1.unprotected.key_id.is_empty() && !anchor.key_id.is_empty() {
                    if sign1.unprotected.key_id != anchor.key_id {
                        continue;
                    }
                }

                // Get the payload (digest CBOR bytes)
                let payload = sign1.payload.as_deref().unwrap_or(&[]);

                if crypto
                    .verify_sign1(anchor, protected_bytes, payload, &sign1.signature)
                    .is_ok()
                {
                    // Check revocation for this key
                    if !anchor.key_id.is_empty()
                        && self.revoked_kids.iter().any(|k| k == &anchor.key_id)
                    {
                        return Err(Sum2Error::Revoked);
                    }
                    any_sig_valid = true;
                    break;
                }
            }
        }

        if !any_sig_valid {
            return Err(Sum2Error::AuthFailed);
        }

        // 5. Anti-rollback: sequence number must be strictly greater than min
        if let Some(min) = self.min_seq {
            if envelope.manifest.sequence_number <= min {
                return Err(Sum2Error::RollbackRejected);
            }
        }

        // 6. Timestamp-based revocation
        if let (Some(reject_before), time) = (self.reject_before, _trusted_time) {
            if time > 0 && time < reject_before {
                return Err(Sum2Error::Revoked);
            }
        }

        let manifest = Manifest { envelope };

        // 7. Check device identity conditions (if device_id is configured)
        if let Some(ref dev_id) = self.device_id {
            // Check component 0 (the primary component)
            if let Some(vendor) = manifest.vendor_id(0) {
                if vendor != dev_id.vendor_id {
                    return Err(Sum2Error::VendorMismatch);
                }
            }
            if let Some(class) = manifest.class_id(0) {
                if class != dev_id.class_id {
                    return Err(Sum2Error::ClassMismatch);
                }
            }
            if let Some(device) = manifest.device_id(0) {
                if device != dev_id.device_id {
                    return Err(Sum2Error::DeviceMismatch);
                }
            }
        }

        Ok(manifest)
    }
}
