//! L2 image manifest builder (fluent API).

use sumo_codec::commands::{CommandItem, CommandSequence, CommandValue};
use sumo_codec::component::ComponentIdentifier;
use sumo_codec::encode::encode_envelope;
use sumo_codec::envelope::{SuitAuthentication, SuitEnvelope};
use sumo_codec::labels::*;
use sumo_codec::manifest::{SeverableMembers, SuitCommon, SuitManifest};
use sumo_codec::parameters::{ParameterValue, SuitParameter};
use sumo_codec::text::{SuitText, TextComponent};
use sumo_codec::types::{DigestAlgorithm, DigestInfo, SemVer, Uuid};

use crate::cose_key::CoseKey;
use crate::error::OffboardError;
use sumo_crypto::CryptoBackend;

/// Builder for L2 single-ECU image manifests.
pub struct ImageManifestBuilder {
    component_id: Vec<String>,
    sequence_number: u64,
    vendor_id: Option<Uuid>,
    class_id: Option<Uuid>,
    device_id: Option<Uuid>,
    version: Option<SemVer>,
    payload_digest: Option<Vec<u8>>,
    payload_size: u64,
    payload_uri: Option<String>,
    fallback_uris: Vec<String>,
    encryption_info: Option<Vec<u8>>,
    integrated_payloads: std::collections::BTreeMap<String, Vec<u8>>,
    security_version: Option<u64>,
    /// Manifest signing time — `iat` (Unix seconds), stamped into the COSE_Sign1
    /// protected header (`{15: {6: iat}}`). REQUIRED: `build` errors if unset, so
    /// no manifest is ever produced without a signed lower bound on real time.
    /// Caller-supplied (never sampled here) so builds/test-vectors are reproducible.
    signing_time: Option<u64>,
    text_vendor_name: Option<String>,
    text_model_name: Option<String>,
    text_model_info: Option<String>,
    text_version: Option<String>,
    text_description: Option<String>,
}

impl ImageManifestBuilder {
    pub fn new() -> Self {
        Self {
            component_id: Vec::new(),
            sequence_number: 0,
            vendor_id: None,
            class_id: None,
            device_id: None,
            version: None,
            payload_digest: None,
            payload_size: 0,
            payload_uri: None,
            fallback_uris: Vec::new(),
            encryption_info: None,
            integrated_payloads: std::collections::BTreeMap::new(),
            security_version: None,
            signing_time: None,
            text_vendor_name: None,
            text_model_name: None,
            text_model_info: None,
            text_version: None,
            text_description: None,
        }
    }

    /// Set the manifest signing time (`iat`, Unix seconds). REQUIRED — see the
    /// `signing_time` field. Sample the clock at the caller's edge and pass it in.
    pub fn signing_time(mut self, unix_secs: u64) -> Self {
        self.signing_time = Some(unix_secs);
        self
    }

    pub fn component_id(mut self, id: Vec<String>) -> Self {
        self.component_id = id;
        self
    }
    pub fn sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number = seq;
        self
    }
    pub fn vendor_id(mut self, v: Uuid) -> Self {
        self.vendor_id = Some(v);
        self
    }
    pub fn class_id(mut self, c: Uuid) -> Self {
        self.class_id = Some(c);
        self
    }
    pub fn device_id(mut self, d: Uuid) -> Self {
        self.device_id = Some(d);
        self
    }
    pub fn sem_ver(mut self, v: SemVer) -> Self {
        self.version = Some(v);
        self
    }
    pub fn payload_digest(mut self, sha256: &[u8], size: u64) -> Self {
        self.payload_digest = Some(sha256.to_vec());
        self.payload_size = size;
        self
    }
    pub fn payload_uri(mut self, uri: String) -> Self {
        self.payload_uri = Some(uri);
        self
    }
    pub fn fallback_uri(mut self, uri: String) -> Self {
        self.fallback_uris.push(uri);
        self
    }
    pub fn encryption_info(mut self, info: &[u8]) -> Self {
        self.encryption_info = Some(info.to_vec());
        self
    }
    pub fn integrated_payload(mut self, key: String, data: Vec<u8>) -> Self {
        self.integrated_payloads.insert(key, data);
        self
    }
    pub fn security_version(mut self, v: u64) -> Self {
        self.security_version = Some(v);
        self
    }
    pub fn text_vendor_name(mut self, s: impl Into<String>) -> Self {
        self.text_vendor_name = Some(s.into());
        self
    }
    pub fn text_model_name(mut self, s: impl Into<String>) -> Self {
        self.text_model_name = Some(s.into());
        self
    }
    pub fn text_model_info(mut self, s: impl Into<String>) -> Self {
        self.text_model_info = Some(s.into());
        self
    }
    pub fn text_version(mut self, s: impl Into<String>) -> Self {
        self.text_version = Some(s.into());
        self
    }
    pub fn text_description(mut self, s: impl Into<String>) -> Self {
        self.text_description = Some(s.into());
        self
    }

    /// Build and sign the SUIT envelope.
    pub fn build(self, signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        let crypto = sumo_crypto::RustCryptoBackend::new();

        // Signing time (iat) is mandatory — every manifest must carry a signed
        // lower bound on real time. Fail loudly rather than emit one without it.
        let iat = self.signing_time.ok_or_else(|| {
            OffboardError::Other("signing_time (iat) is required to build a manifest".into())
        })?;

        // Build component identifier
        let comp = ComponentIdentifier {
            segments: self
                .component_id
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
        };

        // Build shared command sequence with override-parameters
        let mut params = Vec::new();

        if let Some(ref vendor) = self.vendor_id {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_VENDOR_IDENTIFIER,
                value: ParameterValue::VendorId(*vendor),
            });
        }
        if let Some(ref class) = self.class_id {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_CLASS_IDENTIFIER,
                value: ParameterValue::ClassId(*class),
            });
        }
        if let Some(ref device) = self.device_id {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_DEVICE_IDENTIFIER,
                value: ParameterValue::DeviceId(*device),
            });
        }
        if let Some(ref digest_bytes) = self.payload_digest {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_IMAGE_DIGEST,
                value: ParameterValue::ImageDigest(DigestInfo {
                    algorithm: DigestAlgorithm::Sha256,
                    bytes: digest_bytes.clone(),
                }),
            });
            params.push(SuitParameter {
                label: SUIT_PARAMETER_IMAGE_SIZE,
                value: ParameterValue::ImageSize(self.payload_size),
            });
        }
        if let Some(ref uri) = self.payload_uri {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_URI,
                value: ParameterValue::Uri(uri.clone()),
            });
        }
        if let Some(ref enc_info) = self.encryption_info {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_ENCRYPTION_INFO,
                value: ParameterValue::EncryptionInfo(enc_info.clone()),
            });
        }
        if let Some(secver) = self.security_version {
            params.push(SuitParameter {
                label: SUIT_PARAMETER_SECURITY_VERSION,
                value: ParameterValue::SecurityVersion(secver),
            });
        }

        let mut shared_items = Vec::new();
        if !params.is_empty() {
            shared_items.push(CommandItem {
                label: SUIT_DIRECTIVE_OVERRIDE_PARAMETERS,
                value: CommandValue::Parameters(params),
            });
        }

        let is_firmware = self.payload_digest.is_some();

        // Command sequences — only for firmware manifests, not policy-only
        let validate = if is_firmware {
            Some(CommandSequence {
                items: vec![CommandItem {
                    label: SUIT_CONDITION_IMAGE_MATCH,
                    value: CommandValue::ReportingPolicy(0),
                }],
            })
        } else {
            None
        };

        // Install sequence: directive-copy (write to target storage)
        let install = if is_firmware {
            Some(CommandSequence {
                items: vec![CommandItem {
                    label: SUIT_DIRECTIVE_COPY,
                    value: CommandValue::ReportingPolicy(0),
                }],
            })
        } else {
            None
        };

        // Invoke sequence: directive-invoke (boot new firmware)
        let invoke = if is_firmware {
            Some(CommandSequence {
                items: vec![CommandItem {
                    label: SUIT_DIRECTIVE_INVOKE,
                    value: CommandValue::ReportingPolicy(0),
                }],
            })
        } else {
            None
        };

        // Build text metadata (if any text fields set)
        let text = {
            let tc = TextComponent {
                vendor_name: self.text_vendor_name,
                model_name: self.text_model_name,
                vendor_domain: None,
                model_info: self.text_model_info,
                description: None,
                version: self.text_version,
            };
            let has_text = tc.vendor_name.is_some()
                || tc.model_name.is_some()
                || tc.model_info.is_some()
                || tc.version.is_some()
                || self.text_description.is_some();
            if has_text {
                let mut components = std::collections::BTreeMap::new();
                components.insert(0, tc);
                Some(SuitText {
                    description: self.text_description,
                    components,
                })
            } else {
                None
            }
        };

        let manifest = SuitManifest {
            manifest_version: 1,
            sequence_number: self.sequence_number,
            common: SuitCommon {
                components: vec![comp],
                dependencies: Vec::new(),
                shared_sequence: CommandSequence {
                    items: shared_items,
                },
            },
            validate,
            invoke,
            severable: SeverableMembers {
                text,
                install,
                ..SeverableMembers::default()
            },
        };

        // Encode manifest to compute digest
        let manifest_bytes = sumo_codec::encode::encode_manifest(&manifest)?;
        // Hash bstr-wrapped manifest (RFC 9019 / libcsuit "include header")
        let digest_hash = crypto.sha256(&cbor_bstr_wrap(&manifest_bytes));

        let envelope = SuitEnvelope {
            authentication: SuitAuthentication {
                digest: DigestInfo {
                    algorithm: DigestAlgorithm::Sha256,
                    bytes: digest_hash.to_vec(),
                },
                signatures: Vec::new(), // populated by encode_envelope
            },
            manifest,
            integrated_payloads: self.integrated_payloads,
            manifest_bytes: Vec::new(), // populated by encode_envelope
        };

        // Encode and sign
        let signed_bytes = encode_envelope(&envelope, |manifest_bytes| {
            sign_manifest(&crypto, signing_key, manifest_bytes, iat)
        })?;

        Ok(signed_bytes)
    }

    /// Build and sign a SUIT **disable** manifest for this builder's component.
    ///
    /// Mirrors [`build`](Self::build) but emits no firmware payload: the command
    /// sequence is `[set-component-index 0, suit-directive-disable]` and every
    /// severable member is empty, so `has_firmware()` is false. Signed with the
    /// same sw-authority `CoseKey` as a flash manifest, so the device's existing
    /// trust anchor validates it and routes the directive to deactivation.
    pub fn build_disable(self, signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        let crypto = sumo_crypto::RustCryptoBackend::new();

        // Signing time (iat) is mandatory — see the `signing_time` field.
        let iat = self.signing_time.ok_or_else(|| {
            OffboardError::Other("signing_time (iat) is required to build a manifest".into())
        })?;

        // Build component identifier
        let comp = ComponentIdentifier {
            segments: self
                .component_id
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
        };

        // Shared command sequence: select the component, then disable it. No
        // payload, so no override-parameters and no validate/install/invoke.
        let shared_items = vec![
            CommandItem {
                label: SUIT_DIRECTIVE_SET_COMPONENT_INDEX,
                value: CommandValue::ComponentIndex(0),
            },
            CommandItem {
                label: SUIT_DIRECTIVE_DISABLE,
                value: CommandValue::Disable,
            },
        ];

        let manifest = SuitManifest {
            manifest_version: 1,
            sequence_number: self.sequence_number,
            common: SuitCommon {
                components: vec![comp],
                dependencies: Vec::new(),
                shared_sequence: CommandSequence {
                    items: shared_items,
                },
            },
            validate: None,
            invoke: None,
            severable: SeverableMembers::default(),
        };

        // Encode manifest to compute digest
        let manifest_bytes = sumo_codec::encode::encode_manifest(&manifest)?;
        // Hash bstr-wrapped manifest (RFC 9019 / libcsuit "include header")
        let digest_hash = crypto.sha256(&cbor_bstr_wrap(&manifest_bytes));

        let envelope = SuitEnvelope {
            authentication: SuitAuthentication {
                digest: DigestInfo {
                    algorithm: DigestAlgorithm::Sha256,
                    bytes: digest_hash.to_vec(),
                },
                signatures: Vec::new(), // populated by encode_envelope
            },
            manifest,
            integrated_payloads: self.integrated_payloads,
            manifest_bytes: Vec::new(), // populated by encode_envelope
        };

        // Encode and sign
        let signed_bytes = encode_envelope(&envelope, |manifest_bytes| {
            sign_manifest(&crypto, signing_key, manifest_bytes, iat)
        })?;

        Ok(signed_bytes)
    }
}

impl Default for ImageManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Multi-component manifest builder
// =============================================================================

/// A single component in a multi-component manifest.
pub struct ComponentSpec {
    pub id: Vec<String>,
    pub digest: Vec<u8>,
    pub size: u64,
    pub uri: String,
    pub encryption_info: Option<Vec<u8>>,
}

/// Builder for multi-component SUIT manifests (e.g., kernel + rootfs).
///
/// Each component gets its own entry in the manifest with independent
/// digest, URI, and encryption info. The shared sequence uses
/// `SET_COMPONENT_INDEX` to apply parameters per component.
pub struct MultiComponentBuilder {
    components: Vec<ComponentSpec>,
    sequence_number: u64,
    security_version: Option<u64>,
    /// Manifest signing time — `iat` (Unix seconds). REQUIRED (see
    /// `ImageManifestBuilder::signing_time`); `build` errors if unset.
    signing_time: Option<u64>,
    integrated_payloads: std::collections::BTreeMap<String, Vec<u8>>,
    text_version: Option<String>,
    text_model_name: Option<String>,
    text_description: Option<String>,
}

impl MultiComponentBuilder {
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            sequence_number: 0,
            security_version: None,
            signing_time: None,
            integrated_payloads: std::collections::BTreeMap::new(),
            text_version: None,
            text_model_name: None,
            text_description: None,
        }
    }

    pub fn sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number = seq;
        self
    }
    /// Set the manifest signing time (`iat`, Unix seconds). REQUIRED.
    pub fn signing_time(mut self, unix_secs: u64) -> Self {
        self.signing_time = Some(unix_secs);
        self
    }
    pub fn security_version(mut self, v: u64) -> Self {
        self.security_version = Some(v);
        self
    }
    pub fn text_version(mut self, s: impl Into<String>) -> Self {
        self.text_version = Some(s.into());
        self
    }
    pub fn text_model_name(mut self, s: impl Into<String>) -> Self {
        self.text_model_name = Some(s.into());
        self
    }
    pub fn text_description(mut self, s: impl Into<String>) -> Self {
        self.text_description = Some(s.into());
        self
    }

    /// Add a component to the manifest.
    pub fn add_component(mut self, spec: ComponentSpec) -> Self {
        self.components.push(spec);
        self
    }

    /// Add an integrated payload (embedded in the envelope).
    pub fn integrated_payload(mut self, key: String, data: Vec<u8>) -> Self {
        self.integrated_payloads.insert(key, data);
        self
    }

    /// Build and sign the multi-component SUIT envelope.
    pub fn build(self, signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        let crypto = sumo_crypto::RustCryptoBackend::new();

        // Signing time (iat) is mandatory (see ImageManifestBuilder::signing_time).
        let iat = self.signing_time.ok_or_else(|| {
            OffboardError::Other("signing_time (iat) is required to build a manifest".into())
        })?;

        if self.components.is_empty() {
            return Err(OffboardError::Other("no components added".into()));
        }

        // Build component identifiers
        let components: Vec<ComponentIdentifier> = self
            .components
            .iter()
            .map(|c| ComponentIdentifier {
                segments: c.id.iter().map(|s| s.as_bytes().to_vec()).collect(),
            })
            .collect();

        // Build shared command sequence with per-component parameters
        let mut shared_items = Vec::new();

        for (idx, comp) in self.components.iter().enumerate() {
            // SET_COMPONENT_INDEX
            if self.components.len() > 1 {
                shared_items.push(CommandItem {
                    label: SUIT_DIRECTIVE_SET_COMPONENT_INDEX,
                    value: CommandValue::ComponentIndex(idx),
                });
            }

            // OVERRIDE_PARAMETERS for this component
            let mut params = Vec::new();

            params.push(SuitParameter {
                label: SUIT_PARAMETER_IMAGE_DIGEST,
                value: ParameterValue::ImageDigest(DigestInfo {
                    algorithm: DigestAlgorithm::Sha256,
                    bytes: comp.digest.clone(),
                }),
            });
            params.push(SuitParameter {
                label: SUIT_PARAMETER_IMAGE_SIZE,
                value: ParameterValue::ImageSize(comp.size),
            });
            params.push(SuitParameter {
                label: SUIT_PARAMETER_URI,
                value: ParameterValue::Uri(comp.uri.clone()),
            });
            if let Some(ref enc_info) = comp.encryption_info {
                params.push(SuitParameter {
                    label: SUIT_PARAMETER_ENCRYPTION_INFO,
                    value: ParameterValue::EncryptionInfo(enc_info.clone()),
                });
            }

            // Security version on first component only
            if idx == 0 {
                if let Some(secver) = self.security_version {
                    params.push(SuitParameter {
                        label: SUIT_PARAMETER_SECURITY_VERSION,
                        value: ParameterValue::SecurityVersion(secver),
                    });
                }
            }

            shared_items.push(CommandItem {
                label: SUIT_DIRECTIVE_OVERRIDE_PARAMETERS,
                value: CommandValue::Parameters(params),
            });
        }

        // Validate + install + invoke for all components
        let validate = Some(CommandSequence {
            items: vec![CommandItem {
                label: SUIT_CONDITION_IMAGE_MATCH,
                value: CommandValue::ReportingPolicy(0),
            }],
        });
        let install = Some(CommandSequence {
            items: vec![CommandItem {
                label: SUIT_DIRECTIVE_COPY,
                value: CommandValue::ReportingPolicy(0),
            }],
        });
        let invoke = Some(CommandSequence {
            items: vec![CommandItem {
                label: SUIT_DIRECTIVE_INVOKE,
                value: CommandValue::ReportingPolicy(0),
            }],
        });

        // Text metadata
        let text = {
            let tc = TextComponent {
                vendor_name: None,
                model_name: self.text_model_name,
                vendor_domain: None,
                model_info: None,
                description: None,
                version: self.text_version,
            };
            let has_text =
                tc.model_name.is_some() || tc.version.is_some() || self.text_description.is_some();
            if has_text {
                let mut text_components = std::collections::BTreeMap::new();
                text_components.insert(0, tc);
                Some(SuitText {
                    description: self.text_description,
                    components: text_components,
                })
            } else {
                None
            }
        };

        let manifest = SuitManifest {
            manifest_version: 1,
            sequence_number: self.sequence_number,
            common: SuitCommon {
                components,
                dependencies: Vec::new(),
                shared_sequence: CommandSequence {
                    items: shared_items,
                },
            },
            validate,
            invoke,
            severable: SeverableMembers {
                text,
                install,
                ..SeverableMembers::default()
            },
        };

        let manifest_bytes = sumo_codec::encode::encode_manifest(&manifest)?;
        // Hash bstr-wrapped manifest (RFC 9019 / libcsuit "include header")
        let digest_hash = crypto.sha256(&cbor_bstr_wrap(&manifest_bytes));

        let envelope = SuitEnvelope {
            authentication: SuitAuthentication {
                digest: DigestInfo {
                    algorithm: DigestAlgorithm::Sha256,
                    bytes: digest_hash.to_vec(),
                },
                signatures: Vec::new(),
            },
            manifest,
            integrated_payloads: self.integrated_payloads,
            manifest_bytes: Vec::new(),
        };

        let signed_bytes = encode_envelope(&envelope, |manifest_bytes| {
            sign_manifest(&crypto, signing_key, manifest_bytes, iat)
        })?;

        Ok(signed_bytes)
    }
}

impl Default for MultiComponentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Sign manifest bytes, producing a COSE_Sign1 structure.
pub(crate) fn sign_manifest(
    crypto: &dyn CryptoBackend,
    key: &CoseKey,
    manifest_bytes: &[u8],
    iat: u64,
) -> Result<Vec<u8>, sumo_codec::CodecError> {
    // Compute digest over the bstr-wrapped manifest, matching the
    // RFC 9019 convention used by libcsuit ("include header"). The bstr
    // header bytes are part of what is hashed so that interop with C
    // SUIT stacks works.
    let wrapped = cbor_bstr_wrap(manifest_bytes);
    let digest = crypto.sha256(&wrapped);

    // Build digest CBOR as the payload for COSE_Sign1
    let digest_cbor = encode_digest_cbor(&DigestInfo {
        algorithm: DigestAlgorithm::Sha256,
        bytes: digest.to_vec(),
    })?;

    // Build COSE_Sign1 protected header with algorithm
    let alg = key
        .inner()
        .alg
        .as_ref()
        .map(|a| match a {
            coset::RegisteredLabelWithPrivate::Assigned(alg) => *alg as i64,
            _ => -7, // default ES256
        })
        .unwrap_or(-7);

    let protected = encode_protected_header(alg, iat)?;

    // Sign
    let signature = crypto
        .sign(key.inner(), &protected, &digest_cbor)
        .map_err(|_| sumo_codec::CodecError::CborEncode)?;

    // Build COSE_Sign1_Tagged = #6.18([protected, unprotected, payload, signature])
    // Per SUIT (RFC 9019) the auth wrapper requires the CBOR-tagged form,
    // and the payload is detached (Null) — the manifest digest is supplied
    // by the surrounding SUIT_Authentication structure's first array slot.
    use ciborium::value::Value;
    let sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Null,
            Value::Bytes(signature),
        ])),
    );
    let _ = digest_cbor; // signed-over but not embedded (detached)

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&sign1, &mut buf).map_err(|_| sumo_codec::CodecError::CborEncode)?;
    Ok(buf)
}

/// Public re-export so campaign_builder can share the same helper.
pub(crate) fn cbor_bstr_wrap_pub(bytes: &[u8]) -> Vec<u8> {
    cbor_bstr_wrap(bytes)
}

/// Wrap raw bytes in a CBOR byte-string header, returning the on-the-wire
/// bstr encoding. Used so manifest-digest hashes match libcsuit's
/// "include header" convention.
fn cbor_bstr_wrap(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 9);
    let len = bytes.len();
    if len < 24 {
        out.push(0x40 | (len as u8));
    } else if len <= 0xff {
        out.push(0x58);
        out.push(len as u8);
    } else if len <= 0xffff {
        out.push(0x59);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xffff_ffff {
        out.push(0x5a);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(0x5b);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(bytes);
    out
}

fn encode_digest_cbor(digest: &DigestInfo) -> Result<Vec<u8>, sumo_codec::CodecError> {
    use ciborium::value::{Integer, Value};
    let alg = match digest.algorithm {
        DigestAlgorithm::Sha256 => -16i64,
        DigestAlgorithm::Sha384 => -43,
        DigestAlgorithm::Sha512 => -44,
    };
    let arr = Value::Array(vec![
        Value::Integer(Integer::from(alg)),
        Value::Bytes(digest.bytes.clone()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&arr, &mut buf).map_err(|_| sumo_codec::CodecError::CborEncode)?;
    Ok(buf)
}

/// Encode the COSE_Sign1 protected header: `{1: alg, 15: {6: iat}}`.
/// Label 1 is the COSE algorithm; label 15 (RFC 9597 "CWT Claims") carries a
/// CWT Claims Set holding the registered `iat` claim (6) — the manifest signing
/// time in Unix seconds. Because it is in the *protected* header the signature
/// covers it, so `iat` is a signed, unforgeable lower bound on real time.
fn encode_protected_header(alg: i64, iat: u64) -> Result<Vec<u8>, sumo_codec::CodecError> {
    use ciborium::value::{Integer, Value};
    let cwt_claims = Value::Map(vec![(
        Value::Integer(Integer::from(sumo_codec::labels::CWT_CLAIM_IAT)),
        Value::Integer(Integer::from(iat)),
    )]);
    let map = Value::Map(vec![
        (
            Value::Integer(Integer::from(1i64)),
            Value::Integer(Integer::from(alg)),
        ),
        (
            Value::Integer(Integer::from(sumo_codec::labels::COSE_HEADER_CWT_CLAIMS)),
            cwt_claims,
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf).map_err(|_| sumo_codec::CodecError::CborEncode)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sumo_codec::decode::decode_envelope;

    /// Mint a disable manifest for a component and round-trip it through the real
    /// encode/decode: it must be (a) signed, (b) decode with a `CommandValue::Disable`
    /// for the selected component, and (c) carry no firmware payload.
    #[test]
    fn build_disable_mints_a_signed_no_payload_manifest() {
        let key = crate::keygen::generate_signing_key(crate::keygen::ES256).unwrap();

        let bytes = ImageManifestBuilder::new()
            .component_id(vec!["vm1".into()])
            .sequence_number(7)
            .signing_time(1_700_000_000)
            .build_disable(&key)
            .expect("disable manifest builds");

        let env = decode_envelope(&bytes).expect("disable manifest decodes");

        // (a) signed — the auth wrapper carries a COSE_Sign1.
        assert!(
            !env.authentication.signatures.is_empty(),
            "disable manifest must be signed"
        );

        // (b) the shared sequence selects the component, then disables it.
        let items = &env.manifest.common.shared_sequence.items;
        let sci = items
            .iter()
            .find(|c| c.label == SUIT_DIRECTIVE_SET_COMPONENT_INDEX)
            .expect("set-component-index present");
        assert!(matches!(sci.value, CommandValue::ComponentIndex(0)));
        let disable = items
            .iter()
            .find(|c| c.label == SUIT_DIRECTIVE_DISABLE)
            .expect("disable directive present after round-trip");
        assert!(matches!(disable.value, CommandValue::Disable));

        // (c) no firmware payload: no override-parameters (=> no image digest),
        // and no severable install/payload_fetch nor validate/invoke sequences.
        assert!(
            !items
                .iter()
                .any(|c| c.label == SUIT_DIRECTIVE_OVERRIDE_PARAMETERS),
            "disable manifest carries no parameters"
        );
        assert!(env.manifest.severable.install.is_none());
        assert!(env.manifest.severable.payload_fetch.is_none());
        assert!(env.manifest.validate.is_none());
        assert!(env.manifest.invoke.is_none());
        assert!(env.integrated_payloads.is_empty());
    }
}
