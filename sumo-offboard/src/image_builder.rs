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
    version: Option<SemVer>,
    payload_digest: Option<Vec<u8>>,
    payload_size: u64,
    payload_uri: Option<String>,
    fallback_uris: Vec<String>,
    encryption_info: Option<Vec<u8>>,
    integrated_payloads: std::collections::BTreeMap<String, Vec<u8>>,
    security_version: Option<u64>,
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
            version: None,
            payload_digest: None,
            payload_size: 0,
            payload_uri: None,
            fallback_uris: Vec::new(),
            encryption_info: None,
            integrated_payloads: std::collections::BTreeMap::new(),
            security_version: None,
            text_vendor_name: None,
            text_model_name: None,
            text_model_info: None,
            text_version: None,
            text_description: None,
        }
    }

    pub fn component_id(mut self, id: Vec<String>) -> Self { self.component_id = id; self }
    pub fn sequence_number(mut self, seq: u64) -> Self { self.sequence_number = seq; self }
    pub fn vendor_id(mut self, v: Uuid) -> Self { self.vendor_id = Some(v); self }
    pub fn class_id(mut self, c: Uuid) -> Self { self.class_id = Some(c); self }
    pub fn sem_ver(mut self, v: SemVer) -> Self { self.version = Some(v); self }
    pub fn payload_digest(mut self, sha256: &[u8], size: u64) -> Self {
        self.payload_digest = Some(sha256.to_vec());
        self.payload_size = size;
        self
    }
    pub fn payload_uri(mut self, uri: String) -> Self { self.payload_uri = Some(uri); self }
    pub fn fallback_uri(mut self, uri: String) -> Self { self.fallback_uris.push(uri); self }
    pub fn encryption_info(mut self, info: &[u8]) -> Self { self.encryption_info = Some(info.to_vec()); self }
    pub fn integrated_payload(mut self, key: String, data: Vec<u8>) -> Self {
        self.integrated_payloads.insert(key, data);
        self
    }
    pub fn security_version(mut self, v: u64) -> Self { self.security_version = Some(v); self }
    pub fn text_vendor_name(mut self, s: impl Into<String>) -> Self { self.text_vendor_name = Some(s.into()); self }
    pub fn text_model_name(mut self, s: impl Into<String>) -> Self { self.text_model_name = Some(s.into()); self }
    pub fn text_model_info(mut self, s: impl Into<String>) -> Self { self.text_model_info = Some(s.into()); self }
    pub fn text_version(mut self, s: impl Into<String>) -> Self { self.text_version = Some(s.into()); self }
    pub fn text_description(mut self, s: impl Into<String>) -> Self { self.text_description = Some(s.into()); self }

    /// Build and sign the SUIT envelope.
    pub fn build(self, signing_key: &CoseKey) -> Result<Vec<u8>, OffboardError> {
        let crypto = sumo_crypto::RustCryptoBackend::new();

        // Build component identifier
        let comp = ComponentIdentifier {
            segments: self.component_id.iter().map(|s| s.as_bytes().to_vec()).collect(),
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
                shared_sequence: CommandSequence { items: shared_items },
            },
            validate,
            invoke,
            severable: SeverableMembers { text, install, ..SeverableMembers::default() },
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
                signatures: Vec::new(), // populated by encode_envelope
            },
            manifest,
            integrated_payloads: self.integrated_payloads,
            manifest_bytes: Vec::new(), // populated by encode_envelope
        };

        // Encode and sign
        let signed_bytes = encode_envelope(&envelope, |manifest_bytes| {
            sign_manifest(&crypto, signing_key, manifest_bytes)
        })?;

        Ok(signed_bytes)
    }
}

impl Default for ImageManifestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Sign manifest bytes, producing a COSE_Sign1 structure.
pub(crate) fn sign_manifest(
    crypto: &dyn CryptoBackend,
    key: &CoseKey,
    manifest_bytes: &[u8],
) -> Result<Vec<u8>, sumo_codec::CodecError> {
    // Compute digest of manifest bytes
    let digest = crypto.sha256(manifest_bytes);

    // Build digest CBOR as the payload for COSE_Sign1
    let digest_cbor = encode_digest_cbor(&DigestInfo {
        algorithm: DigestAlgorithm::Sha256,
        bytes: digest.to_vec(),
    })?;

    // Build COSE_Sign1 protected header with algorithm
    let alg = key.inner().alg.as_ref().map(|a| match a {
        coset::RegisteredLabelWithPrivate::Assigned(alg) => *alg as i64,
        _ => -7, // default ES256
    }).unwrap_or(-7);

    let protected = encode_protected_header(alg)?;

    // Sign
    let signature = crypto
        .sign(key.inner(), &protected, &digest_cbor)
        .map_err(|_| sumo_codec::CodecError::CborEncode)?;

    // Build COSE_Sign1 = [protected, unprotected, payload, signature]
    use ciborium::value::Value;
    let sign1 = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(Vec::new()),
        Value::Bytes(digest_cbor),
        Value::Bytes(signature),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&sign1, &mut buf)
        .map_err(|_| sumo_codec::CodecError::CborEncode)?;
    Ok(buf)
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
    ciborium::ser::into_writer(&arr, &mut buf)
        .map_err(|_| sumo_codec::CodecError::CborEncode)?;
    Ok(buf)
}

fn encode_protected_header(alg: i64) -> Result<Vec<u8>, sumo_codec::CodecError> {
    use ciborium::value::{Integer, Value};
    let map = Value::Map(vec![(
        Value::Integer(Integer::from(1i64)),
        Value::Integer(Integer::from(alg)),
    )]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf)
        .map_err(|_| sumo_codec::CodecError::CborEncode)?;
    Ok(buf)
}
