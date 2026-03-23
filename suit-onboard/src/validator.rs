//! SUIT envelope validator with trust anchor management.

use std::vec::Vec;

use crate::device_id::DeviceId;
use crate::error::Sum2Error;
use crate::manifest::Manifest;

/// Validates SUIT envelopes against trust anchors and device policy.
pub struct Validator {
    _device_id: Option<DeviceId>,
    _trust_anchors: Vec<Vec<u8>>,
    _revoked_kids: Vec<Vec<u8>>,
    _device_keys: Vec<Vec<u8>>,
    _min_seq: Option<u64>,
    _reject_before: Option<i64>,
}

impl Validator {
    /// Create a new validator with a trust anchor and optional device identity.
    pub fn new(trust_anchor: &[u8], device_id: Option<DeviceId>) -> Self {
        Self {
            _device_id: device_id,
            _trust_anchors: vec![trust_anchor.to_vec()],
            _revoked_kids: Vec::new(),
            _device_keys: Vec::new(),
            _min_seq: None,
            _reject_before: None,
        }
    }

    pub fn add_trust_anchor(&mut self, _key: &[u8]) -> Result<(), Sum2Error> {
        // TODO: Phase 3
        Ok(())
    }

    pub fn revoke_kid(&mut self, _kid: &[u8]) -> Result<(), Sum2Error> {
        // TODO: Phase 3
        Ok(())
    }

    pub fn add_device_key(&mut self, _key: &[u8], _kid: &[u8]) -> Result<(), Sum2Error> {
        // TODO: Phase 3
        Ok(())
    }

    pub fn set_min_sequence(&mut self, _seq: u64) {
        // TODO: Phase 3
    }

    pub fn set_reject_before(&mut self, _timestamp: i64) {
        // TODO: Phase 3
    }

    /// Validate a SUIT envelope and return the parsed manifest on success.
    pub fn validate_envelope(
        &self,
        _envelope: &[u8],
        _trusted_time: i64,
    ) -> Result<Manifest, Sum2Error> {
        // TODO: Phase 3
        Err(Sum2Error::InvalidEnvelope)
    }
}
