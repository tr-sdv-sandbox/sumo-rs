//! L1 campaign manifest builder (fluent API).

use std::collections::BTreeMap;

use sumo_codec::commands::{CommandItem, CommandSequence, CommandValue};
use sumo_codec::component::{ComponentIdentifier, DependencyInfo};
use sumo_codec::encode::encode_envelope;
use sumo_codec::envelope::{SuitAuthentication, SuitEnvelope};
use sumo_codec::labels::*;
use sumo_codec::manifest::{SeverableMembers, SuitCommon, SuitManifest};
use sumo_codec::parameters::{ParameterValue, SuitParameter};
use sumo_codec::types::{DigestAlgorithm, DigestInfo, Uuid};

use crate::cose_key::CoseKey;
use crate::error::OffboardError;
use crate::image_builder::sign_manifest;
use sumo_crypto::CryptoBackend;

/// A dependency in a campaign (external URI or integrated payload).
struct CampaignDep {
    fetch_uri: Option<String>,
    integrated_key: Option<String>,
    l2_envelope: Vec<u8>,
}

/// Builder for L1 campaign manifests that orchestrate multiple L2 image updates.
pub struct CampaignBuilder {
    sequence_number: u64,
    vendor_id: Option<Uuid>,
    class_id: Option<Uuid>,
    deps: Vec<CampaignDep>,
}

impl CampaignBuilder {
    pub fn new() -> Self {
        Self {
            sequence_number: 0,
            vendor_id: None,
            class_id: None,
            deps: Vec::new(),
        }
    }

    pub fn sequence_number(mut self, seq: u64) -> Self { self.sequence_number = seq; self }
    pub fn vendor_id(mut self, v: Uuid) -> Self { self.vendor_id = Some(v); self }
    pub fn class_id(mut self, c: Uuid) -> Self { self.class_id = Some(c); self }

    /// Add an L2 image dependency fetched from a URI.
    pub fn add_image(mut self, fetch_uri: String, l2_envelope: &[u8]) -> Self {
        self.deps.push(CampaignDep {
            fetch_uri: Some(fetch_uri),
            integrated_key: None,
            l2_envelope: l2_envelope.to_vec(),
        });
        self
    }

    /// Add an L2 image dependency integrated (embedded) in the campaign.
    pub fn add_integrated_image(mut self, key: String, l2_envelope: &[u8]) -> Self {
        self.deps.push(CampaignDep {
            fetch_uri: None,
            integrated_key: Some(key),
            l2_envelope: l2_envelope.to_vec(),
        });
        self
    }

    /// Build and sign the campaign SUIT envelope.
    pub fn build(self, signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        let crypto = sumo_crypto::RustCryptoBackend::new();

        if self.deps.is_empty() {
            return Err(OffboardError::Other("campaign must have at least one dependency".into()));
        }

        // Build dependencies and component identifiers
        let mut dependencies = Vec::new();
        let mut components = Vec::new();
        let mut integrated_payloads = BTreeMap::new();

        // Build dependency_resolution sequence items
        let mut dep_res_items: Vec<CommandItem> = Vec::new();

        for (idx, dep) in self.deps.iter().enumerate() {
            dependencies.push(DependencyInfo {
                index: idx,
                prefix: None,
            });

            // Component ID for this dependency
            components.push(ComponentIdentifier {
                segments: vec![format!("dep-{idx}").into_bytes()],
            });

            // Set component index
            dep_res_items.push(CommandItem {
                label: SUIT_DIRECTIVE_SET_COMPONENT_INDEX,
                value: CommandValue::ComponentIndex(idx),
            });

            // URI parameter
            let uri = if let Some(ref key) = dep.integrated_key {
                // Integrated: URI is "#key", store with '#' prefix to match SUIT spec
                let uri = format!("#{key}");
                integrated_payloads.insert(uri.clone(), dep.l2_envelope.clone());
                uri
            } else if let Some(ref uri) = dep.fetch_uri {
                uri.clone()
            } else {
                continue;
            };

            dep_res_items.push(CommandItem {
                label: SUIT_DIRECTIVE_OVERRIDE_PARAMETERS,
                value: CommandValue::Parameters(vec![SuitParameter {
                    label: SUIT_PARAMETER_URI,
                    value: ParameterValue::Uri(uri),
                }]),
            });

            // Fetch directive
            dep_res_items.push(CommandItem {
                label: SUIT_DIRECTIVE_FETCH,
                value: CommandValue::ReportingPolicy(0),
            });
        }

        // Build shared sequence with vendor/class IDs
        let mut shared_params = Vec::new();
        if let Some(ref vendor) = self.vendor_id {
            shared_params.push(SuitParameter {
                label: SUIT_PARAMETER_VENDOR_IDENTIFIER,
                value: ParameterValue::VendorId(*vendor),
            });
        }
        if let Some(ref class) = self.class_id {
            shared_params.push(SuitParameter {
                label: SUIT_PARAMETER_CLASS_IDENTIFIER,
                value: ParameterValue::ClassId(*class),
            });
        }

        let mut shared_items = Vec::new();
        if !shared_params.is_empty() {
            shared_items.push(CommandItem {
                label: SUIT_DIRECTIVE_OVERRIDE_PARAMETERS,
                value: CommandValue::Parameters(shared_params),
            });
        }

        // Build install sequence: process-dependency for each dep
        // This installs all ECUs before any is invoked.
        let mut install_items = Vec::new();
        for idx in 0..self.deps.len() {
            install_items.push(CommandItem {
                label: SUIT_DIRECTIVE_SET_COMPONENT_INDEX,
                value: CommandValue::ComponentIndex(idx),
            });
            install_items.push(CommandItem {
                label: SUIT_DIRECTIVE_PROCESS_DEPENDENCY,
                value: CommandValue::ReportingPolicy(0),
            });
        }

        // Build validate sequence: verify all dependencies after install
        let mut validate_items = Vec::new();
        for idx in 0..self.deps.len() {
            validate_items.push(CommandItem {
                label: SUIT_DIRECTIVE_SET_COMPONENT_INDEX,
                value: CommandValue::ComponentIndex(idx),
            });
            validate_items.push(CommandItem {
                label: SUIT_CONDITION_DEPENDENCY_INTEGRITY,
                value: CommandValue::ReportingPolicy(0),
            });
        }

        // Build invoke sequence: boot all ECUs after validation
        let mut invoke_items = Vec::new();
        for idx in 0..self.deps.len() {
            invoke_items.push(CommandItem {
                label: SUIT_DIRECTIVE_SET_COMPONENT_INDEX,
                value: CommandValue::ComponentIndex(idx),
            });
            invoke_items.push(CommandItem {
                label: SUIT_DIRECTIVE_INVOKE,
                value: CommandValue::ReportingPolicy(0),
            });
        }

        let manifest = SuitManifest {
            manifest_version: 1,
            sequence_number: self.sequence_number,
            common: SuitCommon {
                components,
                dependencies,
                shared_sequence: CommandSequence { items: shared_items },
            },
            validate: Some(CommandSequence { items: validate_items }),
            invoke: Some(CommandSequence { items: invoke_items }),
            severable: SeverableMembers {
                dependency_resolution: Some(CommandSequence { items: dep_res_items }),
                install: Some(CommandSequence { items: install_items }),
                payload_fetch: None,
                text: None,
            },
        };

        // Encode manifest to compute digest
        let manifest_bytes = sumo_codec::encode::encode_manifest(&manifest)?;
        let digest_hash = crypto.sha256(&manifest_bytes);

        let envelope = SuitEnvelope {
            authentication: SuitAuthentication {
                digest: DigestInfo {
                    algorithm: DigestAlgorithm::Sha256,
                    bytes: digest_hash.to_vec(),
                },
                signatures: Vec::new(),
            },
            manifest,
            integrated_payloads,
            manifest_bytes: Vec::new(),
        };

        let signed_bytes = encode_envelope(&envelope, |manifest_bytes| {
            sign_manifest(&crypto, signing_key, manifest_bytes)
        })?;

        Ok(signed_bytes)
    }
}

impl Default for CampaignBuilder {
    fn default() -> Self {
        Self::new()
    }
}
