//! L2 image manifest builder (fluent API).

use suit_codec::types::{SemVer, Uuid};

use crate::cose_key::CoseKey;
use crate::error::OffboardError;

/// Builder for L2 single-ECU image manifests.
pub struct ImageManifestBuilder {
    _component_id: Vec<String>,
    _sequence_number: u64,
    _vendor_id: Option<Uuid>,
    _class_id: Option<Uuid>,
    _version: Option<SemVer>,
    _payload_digest: Option<Vec<u8>>,
    _payload_size: u64,
    _payload_uri: Option<String>,
    _fallback_uris: Vec<String>,
    _encryption_info: Option<Vec<u8>>,
}

impl ImageManifestBuilder {
    pub fn new() -> Self {
        Self {
            _component_id: Vec::new(),
            _sequence_number: 0,
            _vendor_id: None,
            _class_id: None,
            _version: None,
            _payload_digest: None,
            _payload_size: 0,
            _payload_uri: None,
            _fallback_uris: Vec::new(),
            _encryption_info: None,
        }
    }

    pub fn component_id(mut self, id: Vec<String>) -> Self { self._component_id = id; self }
    pub fn sequence_number(mut self, seq: u64) -> Self { self._sequence_number = seq; self }
    pub fn vendor_id(mut self, v: Uuid) -> Self { self._vendor_id = Some(v); self }
    pub fn class_id(mut self, c: Uuid) -> Self { self._class_id = Some(c); self }
    pub fn sem_ver(mut self, v: SemVer) -> Self { self._version = Some(v); self }
    pub fn payload_digest(mut self, sha256: &[u8], size: u64) -> Self {
        self._payload_digest = Some(sha256.to_vec());
        self._payload_size = size;
        self
    }
    pub fn payload_uri(mut self, uri: String) -> Self { self._payload_uri = Some(uri); self }
    pub fn fallback_uri(mut self, uri: String) -> Self { self._fallback_uris.push(uri); self }
    pub fn encryption_info(mut self, info: &[u8]) -> Self { self._encryption_info = Some(info.to_vec()); self }

    /// Build and sign the SUIT envelope.
    pub fn build(self, _signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        // TODO: Phase 7
        Err(OffboardError::Other("not implemented".into()))
    }
}

impl Default for ImageManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}
