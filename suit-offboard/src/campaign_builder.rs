//! L1 campaign manifest builder (fluent API).

use suit_codec::types::Uuid;

use crate::cose_key::CoseKey;
use crate::error::OffboardError;

/// A dependency in a campaign (external URI or integrated payload).
struct CampaignDep {
    fetch_uri: Option<String>,
    integrated_key: Option<String>,
    l2_envelope: Vec<u8>,
}

/// Builder for L1 campaign manifests that orchestrate multiple L2 image updates.
pub struct CampaignBuilder {
    _sequence_number: u64,
    _vendor_id: Option<Uuid>,
    _class_id: Option<Uuid>,
    _deps: Vec<CampaignDep>,
}

impl CampaignBuilder {
    pub fn new() -> Self {
        Self {
            _sequence_number: 0,
            _vendor_id: None,
            _class_id: None,
            _deps: Vec::new(),
        }
    }

    pub fn sequence_number(mut self, seq: u64) -> Self { self._sequence_number = seq; self }
    pub fn vendor_id(mut self, v: Uuid) -> Self { self._vendor_id = Some(v); self }
    pub fn class_id(mut self, c: Uuid) -> Self { self._class_id = Some(c); self }

    /// Add an L2 image dependency fetched from a URI.
    pub fn add_image(mut self, fetch_uri: String, l2_envelope: &[u8]) -> Self {
        self._deps.push(CampaignDep {
            fetch_uri: Some(fetch_uri),
            integrated_key: None,
            l2_envelope: l2_envelope.to_vec(),
        });
        self
    }

    /// Add an L2 image dependency integrated (embedded) in the campaign.
    pub fn add_integrated_image(mut self, key: String, l2_envelope: &[u8]) -> Self {
        self._deps.push(CampaignDep {
            fetch_uri: None,
            integrated_key: Some(key),
            l2_envelope: l2_envelope.to_vec(),
        });
        self
    }

    /// Build and sign the campaign SUIT envelope.
    pub fn build(self, _signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        // TODO: Phase 7
        Err(OffboardError::Other("not implemented".into()))
    }
}

impl Default for CampaignBuilder {
    fn default() -> Self {
        Self::new()
    }
}
