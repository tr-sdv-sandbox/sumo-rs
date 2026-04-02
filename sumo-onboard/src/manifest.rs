//! Parsed SUIT manifest with accessor methods.

use sumo_codec::commands::{CommandSequence, CommandValue};
use sumo_codec::envelope::SuitEnvelope;
use sumo_codec::labels::*;
use sumo_codec::parameters::ParameterValue;
use sumo_codec::types::{DigestInfo, Uuid, VersionMatch};

/// A validated SUIT manifest with convenient accessor methods.
#[derive(Debug)]
pub struct Manifest {
    pub envelope: SuitEnvelope,
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

    /// Get the CBOR-encoded component identifier for the given index.
    pub fn component_id(&self, index: usize) -> Option<&[Vec<u8>]> {
        self.envelope
            .manifest
            .common
            .components
            .get(index)
            .map(|c| c.segments.as_slice())
    }

    pub fn image_size(&self, component: usize) -> Option<u64> {
        self.find_param(component, SUIT_PARAMETER_IMAGE_SIZE)
            .and_then(|p| match &p.value {
                ParameterValue::ImageSize(s) => Some(*s),
                _ => None,
            })
    }

    pub fn image_digest(&self, component: usize) -> Option<(&DigestInfo,)> {
        self.find_param(component, SUIT_PARAMETER_IMAGE_DIGEST)
            .and_then(|p| match &p.value {
                ParameterValue::ImageDigest(d) => Some((d,)),
                _ => None,
            })
    }

    pub fn vendor_id(&self, component: usize) -> Option<Uuid> {
        self.find_param(component, SUIT_PARAMETER_VENDOR_IDENTIFIER)
            .and_then(|p| match &p.value {
                ParameterValue::VendorId(u) => Some(*u),
                _ => None,
            })
    }

    pub fn class_id(&self, component: usize) -> Option<Uuid> {
        self.find_param(component, SUIT_PARAMETER_CLASS_IDENTIFIER)
            .and_then(|p| match &p.value {
                ParameterValue::ClassId(u) => Some(*u),
                _ => None,
            })
    }

    pub fn device_id(&self, component: usize) -> Option<Uuid> {
        self.find_param(component, SUIT_PARAMETER_DEVICE_IDENTIFIER)
            .and_then(|p| match &p.value {
                ParameterValue::DeviceId(u) => Some(*u),
                _ => None,
            })
    }

    pub fn version(&self, component: usize) -> Option<&VersionMatch> {
        self.find_param(component, SUIT_PARAMETER_VERSION)
            .and_then(|p| match &p.value {
                ParameterValue::Version(v) => Some(v),
                _ => None,
            })
    }

    /// Get the security version (custom parameter -257) for anti-rollback.
    ///
    /// This is separate from sequence_number: sequence_number is for build
    /// ordering/replay protection; security_version is the anti-rollback
    /// floor that advances only on explicit commit.
    pub fn security_version(&self, component: usize) -> Option<u64> {
        self.find_param(component, SUIT_PARAMETER_SECURITY_VERSION)
            .and_then(|p| match &p.value {
                ParameterValue::SecurityVersion(v) => Some(*v),
                _ => None,
            })
    }

    pub fn uri(&self, component: usize) -> Option<&str> {
        // Search install → payload_fetch → shared sequence
        let sequences = [
            self.envelope.manifest.severable.install.as_ref(),
            self.envelope.manifest.severable.payload_fetch.as_ref(),
            Some(&self.envelope.manifest.common.shared_sequence),
        ];
        for seq in sequences.into_iter().flatten() {
            if let Some(p) = find_param_in_seq(seq, component, SUIT_PARAMETER_URI) {
                if let ParameterValue::Uri(u) = &p.value {
                    return Some(u.as_str());
                }
            }
        }
        None
    }

    pub fn encryption_info(&self, component: usize) -> Option<&[u8]> {
        // Search shared → install → payload_fetch
        let sequences = [
            Some(&self.envelope.manifest.common.shared_sequence),
            self.envelope.manifest.severable.install.as_ref(),
            self.envelope.manifest.severable.payload_fetch.as_ref(),
        ];
        for seq in sequences.into_iter().flatten() {
            if let Some(p) = find_param_in_seq(seq, component, SUIT_PARAMETER_ENCRYPTION_INFO) {
                if let ParameterValue::EncryptionInfo(info) = &p.value {
                    return Some(info.as_slice());
                }
            }
        }
        None
    }

    /// Get an integrated payload by URI key.
    pub fn integrated_payload(&self, key: &str) -> Option<&[u8]> {
        self.envelope
            .integrated_payloads
            .get(key)
            .map(|v| v.as_slice())
    }

    /// Get the fetch URI for a dependency by dependency index.
    ///
    /// Searches dependency_resolution → install → shared sequence for a URI
    /// parameter associated with the given dependency index.
    pub fn dependency_uri(&self, dep_index: usize) -> Option<&str> {
        let sequences = [
            self.envelope.manifest.severable.dependency_resolution.as_ref(),
            self.envelope.manifest.severable.install.as_ref(),
            Some(&self.envelope.manifest.common.shared_sequence),
        ];
        for seq in sequences.into_iter().flatten() {
            if let Some(p) = find_param_in_seq(seq, dep_index, SUIT_PARAMETER_URI) {
                if let ParameterValue::Uri(u) = &p.value {
                    return Some(u.as_str());
                }
            }
        }
        None
    }

    // --- Text accessors ---

    pub fn text_vendor_name(&self, component: usize) -> Option<&str> {
        self.text_component_field(component, |tc| tc.vendor_name.as_deref())
    }

    pub fn text_model_name(&self, component: usize) -> Option<&str> {
        self.text_component_field(component, |tc| tc.model_name.as_deref())
    }

    pub fn text_model_info(&self, component: usize) -> Option<&str> {
        self.text_component_field(component, |tc| tc.model_info.as_deref())
    }

    pub fn text_version(&self, component: usize) -> Option<&str> {
        self.text_component_field(component, |tc| tc.version.as_deref())
    }

    pub fn text_description(&self) -> Option<&str> {
        self.envelope
            .manifest
            .severable
            .text
            .as_ref()
            .and_then(|t| t.description.as_deref())
    }

    // --- Command sequence presence ---

    /// True if the manifest has a payload fetch sequence (firmware to download).
    pub fn has_payload_fetch(&self) -> bool {
        self.envelope.manifest.severable.payload_fetch.is_some()
    }

    /// True if the manifest has an install sequence (firmware to write).
    pub fn has_install(&self) -> bool {
        self.envelope.manifest.severable.install.is_some()
    }

    /// True if the manifest has an invoke sequence (boot/execute after install).
    pub fn has_invoke(&self) -> bool {
        self.envelope.manifest.invoke.is_some()
    }

    /// True if the manifest has a validate sequence (hash verification).
    pub fn has_validate(&self) -> bool {
        self.envelope.manifest.validate.is_some()
    }

    /// True if this manifest carries a firmware payload (has digest).
    /// False for policy-only manifests (CRL, config updates).
    pub fn has_firmware(&self) -> bool {
        self.image_digest(0).is_some()
    }

    /// Raw envelope reference (for decryptor/orchestrator access).
    pub fn envelope(&self) -> &SuitEnvelope {
        &self.envelope
    }

    // --- Internal helpers ---

    /// Find a parameter for a given component index in the shared sequence.
    fn find_param(
        &self,
        component: usize,
        param_label: i64,
    ) -> Option<&sumo_codec::parameters::SuitParameter> {
        find_param_in_seq(
            &self.envelope.manifest.common.shared_sequence,
            component,
            param_label,
        )
    }

    fn text_component_field<'a>(
        &'a self,
        component: usize,
        f: impl Fn(&'a sumo_codec::text::TextComponent) -> Option<&'a str>,
    ) -> Option<&'a str> {
        self.envelope
            .manifest
            .severable
            .text
            .as_ref()
            .and_then(|t| t.components.get(&component))
            .and_then(f)
    }
}

/// Search a command sequence for a parameter at a given component index.
///
/// Tracks the current component index via SET_COMPONENT_INDEX directives,
/// then looks for SET_PARAMETERS or OVERRIDE_PARAMETERS that contain the
/// requested parameter label.
fn find_param_in_seq<'a>(
    seq: &'a CommandSequence,
    component: usize,
    param_label: i64,
) -> Option<&'a sumo_codec::parameters::SuitParameter> {
    let mut current_index: usize = 0;

    for item in &seq.items {
        match (&item.value, item.label) {
            (CommandValue::ComponentIndex(idx), SUIT_DIRECTIVE_SET_COMPONENT_INDEX) => {
                current_index = *idx;
            }
            (CommandValue::Parameters(params), label)
                if (label == SUIT_DIRECTIVE_SET_PARAMETERS
                    || label == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS)
                    && current_index == component =>
            {
                if let Some(p) = params.iter().find(|p| p.label == param_label) {
                    return Some(p);
                }
            }
            _ => {}
        }
    }
    None
}
