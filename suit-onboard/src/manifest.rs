//! Parsed SUIT manifest with accessor methods.

use suit_codec::envelope::SuitEnvelope;
use suit_codec::types::{DigestAlgorithm, VersionMatch};

/// A validated SUIT manifest with convenient accessor methods.
pub struct Manifest {
    pub(crate) envelope: SuitEnvelope,
}

impl Manifest {
    pub fn sequence_number(&self) -> u64 {
        self.envelope.manifest.sequence_number
    }

    pub fn component_count(&self) -> usize {
        self.envelope.manifest.common.components.len()
    }

    pub fn dependency_count(&self) -> usize {
        self.envelope.manifest.common.dependencies.len()
    }

    pub fn is_campaign(&self) -> bool {
        self.dependency_count() > 0
    }

    pub fn component_id(&self, _index: usize) -> Option<&[u8]> {
        // TODO: Phase 3
        None
    }

    pub fn image_size(&self, _component: usize) -> Option<u64> {
        // TODO: Phase 3
        None
    }

    pub fn image_digest(&self, _component: usize) -> Option<(&[u8], DigestAlgorithm)> {
        // TODO: Phase 3
        None
    }

    pub fn vendor_id(&self, _component: usize) -> Option<[u8; 16]> {
        // TODO: Phase 3
        None
    }

    pub fn class_id(&self, _component: usize) -> Option<[u8; 16]> {
        // TODO: Phase 3
        None
    }

    pub fn device_id(&self, _component: usize) -> Option<[u8; 16]> {
        // TODO: Phase 3
        None
    }

    pub fn version(&self, _component: usize) -> Option<VersionMatch> {
        // TODO: Phase 3
        None
    }

    pub fn text_vendor_name(&self, _component: usize) -> Option<&str> {
        // TODO: Phase 3
        None
    }

    pub fn text_model_name(&self, _component: usize) -> Option<&str> {
        // TODO: Phase 3
        None
    }

    pub fn text_model_info(&self, _component: usize) -> Option<&str> {
        // TODO: Phase 3
        None
    }

    pub fn text_version(&self, _component: usize) -> Option<&str> {
        // TODO: Phase 3
        None
    }

    pub fn text_description(&self) -> Option<&str> {
        // TODO: Phase 3
        None
    }
}
