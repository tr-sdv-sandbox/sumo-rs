//! SUIT envelope decoding from CBOR bytes.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::commands::{CommandItem, CommandSequence, CommandValue};
use crate::component::{ComponentIdentifier, DependencyInfo};
use crate::envelope::{SuitAuthentication, SuitEnvelope};
use crate::error::CodecError;
use crate::labels::*;
use crate::manifest::{SeverableMembers, SuitCommon, SuitManifest};
use crate::parameters::{ParameterValue, SuitParameter};
use crate::text::{SuitText, TextComponent};
use crate::types::{DigestAlgorithm, DigestInfo, Uuid, VersionComparison, VersionMatch};

/// Decode a SUIT envelope from CBOR bytes.
pub fn decode_envelope(data: &[u8]) -> Result<SuitEnvelope, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;

    // Handle optional Tag 107
    let map = match &value {
        Value::Tag(107, inner) => as_map(inner)?,
        Value::Map(_) => as_map(&value)?,
        _ => return Err(CodecError::CborDecode),
    };

    // Extract authentication wrapper (key 2)
    let auth_bstr = get_bstr_from_map(map, SUIT_AUTHENTICATION_WRAPPER)?;
    let authentication = decode_auth_wrapper(&auth_bstr)?;

    // Extract manifest bytes (key 3)
    let manifest_bytes = get_bstr_from_map(map, SUIT_MANIFEST)?;
    let manifest_value: Value =
        ciborium::de::from_reader(manifest_bytes.as_slice()).map_err(|_| CodecError::CborDecode)?;
    let manifest_map = as_map(&manifest_value)?;

    // Decode manifest
    let mut manifest = decode_manifest(manifest_map)?;

    // Extract severable members from envelope (keys 15, 16, 20, 23)
    // These override digest-only references in the manifest
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_SEVERED_DEPENDENCY_RESOLUTION) {
        manifest.severable.dependency_resolution = Some(decode_command_sequence(&bstr)?);
    }
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_SEVERED_PAYLOAD_FETCH) {
        manifest.severable.payload_fetch = Some(decode_command_sequence(&bstr)?);
    }
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_SEVERED_INSTALL) {
        manifest.severable.install = Some(decode_command_sequence(&bstr)?);
    }
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_SEVERED_TEXT) {
        manifest.severable.text = Some(decode_text(&bstr)?);
    }

    // Extract integrated payloads (text string keys)
    let mut integrated_payloads = BTreeMap::new();
    for (k, v) in map {
        if let Value::Text(key) = k {
            if let Value::Bytes(payload) = v {
                integrated_payloads.insert(key.clone(), payload.clone());
            }
        }
    }

    Ok(SuitEnvelope {
        authentication,
        manifest,
        integrated_payloads,
        manifest_bytes,
    })
}

// --- Authentication ---

fn decode_auth_wrapper(data: &[u8]) -> Result<SuitAuthentication, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;
    let arr = as_array(&value)?;
    if arr.is_empty() {
        return Err(CodecError::MissingField("auth_wrapper digest"));
    }

    // First element: bstr containing SUIT_Digest CBOR
    let digest_bstr = as_bstr(&arr[0])?;
    let digest = decode_digest_from_bstr(&digest_bstr)?;

    // Remaining elements: COSE_Sign1 / COSE_Mac0 (raw bstr)
    let mut signatures = Vec::new();
    for sig in &arr[1..] {
        signatures.push(as_bstr(sig)?);
    }

    Ok(SuitAuthentication { digest, signatures })
}

// --- Manifest ---

fn decode_manifest(
    map: &[(Value, Value)],
) -> Result<SuitManifest, CodecError> {
    let version = get_uint_from_map(map, SUIT_MANIFEST_VERSION)? as u32;
    if version != 1 {
        return Err(CodecError::UnsupportedVersion(version));
    }

    let sequence_number = get_uint_from_map(map, SUIT_MANIFEST_SEQUENCE_NUMBER)?;

    // Common (key 3, bstr-wrapped)
    let common_bstr = get_bstr_from_map(map, SUIT_COMMON)?;
    let common_value: Value =
        ciborium::de::from_reader(common_bstr.as_slice()).map_err(|_| CodecError::CborDecode)?;
    let common = decode_common(as_map(&common_value)?)?;

    // Validate (key 7, optional bstr-wrapped command sequence)
    let validate = try_get_bstr_from_map(map, SUIT_VALIDATE)
        .map(|b| decode_command_sequence(&b))
        .transpose()?;

    // Invoke (key 9, optional)
    let invoke = try_get_bstr_from_map(map, SUIT_INVOKE)
        .map(|b| decode_command_sequence(&b))
        .transpose()?;

    // Severable members that may be inline or digest-only
    let mut severable = SeverableMembers::default();

    // Dependency resolution (key 15)
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_DEPENDENCY_RESOLUTION) {
        // Could be a digest or a command sequence — try command sequence first
        if let Ok(seq) = decode_command_sequence(&bstr) {
            severable.dependency_resolution = Some(seq);
        }
        // If it's a digest, the actual sequence is in the severed envelope member
    }

    // Payload fetch (key 16)
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_PAYLOAD_FETCH) {
        if let Ok(seq) = decode_command_sequence(&bstr) {
            severable.payload_fetch = Some(seq);
        }
    }

    // Install (key 20)
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_INSTALL) {
        if let Ok(seq) = decode_command_sequence(&bstr) {
            severable.install = Some(seq);
        }
    }

    // Text (key 23)
    if let Some(bstr) = try_get_bstr_from_map(map, SUIT_TEXT) {
        if let Ok(text) = decode_text(&bstr) {
            severable.text = Some(text);
        }
    }

    Ok(SuitManifest {
        manifest_version: version,
        sequence_number,
        common,
        validate,
        invoke,
        severable,
    })
}

// --- Common ---

fn decode_common(map: &[(Value, Value)]) -> Result<SuitCommon, CodecError> {
    let mut common = SuitCommon::default();

    // Dependencies (key 1, optional map)
    if let Some(val) = try_get_from_map(map, SUIT_DEPENDENCIES) {
        let dep_map = as_map(val)?;
        for (k, v) in dep_map {
            let index = as_uint(k)? as usize;
            let dep_meta_map = as_map(v)?;
            let prefix = try_get_from_map(dep_meta_map, SUIT_DEPENDENCY_PREFIX)
                .map(|p| {
                    let bstr = as_bstr(p)?;
                    decode_component_id_from_cbor(&bstr)
                })
                .transpose()?;
            common.dependencies.push(DependencyInfo { index, prefix });
        }
    }

    // Components (key 2, array of component identifiers)
    if let Some(val) = try_get_from_map(map, SUIT_COMPONENTS) {
        let arr = as_array(val)?;
        for comp in arr {
            let segments_arr = as_array(comp)?;
            let mut segments = Vec::new();
            for seg in segments_arr {
                segments.push(as_bstr(seg)?);
            }
            common.components.push(ComponentIdentifier { segments });
        }
    }

    // Shared sequence (key 4, optional bstr-wrapped command sequence)
    if let Some(bstr) = try_get_bstr_by_key(map, SUIT_SHARED_SEQUENCE) {
        common.shared_sequence = decode_command_sequence(&bstr)?;
    }

    Ok(common)
}

// --- Command Sequence ---

fn decode_command_sequence(data: &[u8]) -> Result<CommandSequence, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;
    let arr = as_array(&value)?;

    // Flat array of [label, value, label, value, ...]
    if arr.len() % 2 != 0 {
        return Err(CodecError::InvalidValue("command sequence odd length"));
    }

    let mut items = Vec::new();
    for chunk in arr.chunks(2) {
        let label = as_int(&chunk[0])?;
        let value = &chunk[1];
        let cmd = decode_command_item(label, value)?;
        items.push(cmd);
    }

    Ok(CommandSequence { items })
}

fn decode_command_item(label: i64, value: &Value) -> Result<CommandItem, CodecError> {
    let cmd_value = match label {
        SUIT_DIRECTIVE_SET_COMPONENT_INDEX => {
            let idx = as_uint(value)? as usize;
            CommandValue::ComponentIndex(idx)
        }
        SUIT_DIRECTIVE_SET_PARAMETERS | SUIT_DIRECTIVE_OVERRIDE_PARAMETERS => {
            let param_map = as_map(value)?;
            let params = decode_parameters(param_map)?;
            CommandValue::Parameters(params)
        }
        _ => {
            // Conditions and other directives take a uint reporting policy
            let rp = as_uint(value).unwrap_or(0);
            CommandValue::ReportingPolicy(rp)
        }
    };

    Ok(CommandItem {
        label,
        value: cmd_value,
    })
}

// --- Parameters ---

fn decode_parameters(map: &[(Value, Value)]) -> Result<Vec<SuitParameter>, CodecError> {
    let mut params = Vec::new();
    for (k, v) in map {
        let label = as_int(k)?;
        let value = decode_parameter_value(label, v)?;
        params.push(SuitParameter { label, value });
    }
    Ok(params)
}

fn decode_parameter_value(label: i64, value: &Value) -> Result<ParameterValue, CodecError> {
    match label {
        SUIT_PARAMETER_VENDOR_IDENTIFIER => {
            let bytes = as_bstr(value)?;
            Ok(ParameterValue::VendorId(uuid_from_bytes(&bytes)?))
        }
        SUIT_PARAMETER_CLASS_IDENTIFIER => {
            let bytes = as_bstr(value)?;
            Ok(ParameterValue::ClassId(uuid_from_bytes(&bytes)?))
        }
        SUIT_PARAMETER_DEVICE_IDENTIFIER => {
            let bytes = as_bstr(value)?;
            Ok(ParameterValue::DeviceId(uuid_from_bytes(&bytes)?))
        }
        SUIT_PARAMETER_IMAGE_DIGEST => {
            // bstr-wrapped digest CBOR: [alg_id, digest_bytes]
            let bstr = as_bstr(value)?;
            let digest = decode_digest_from_bstr(&bstr)?;
            Ok(ParameterValue::ImageDigest(digest))
        }
        SUIT_PARAMETER_IMAGE_SIZE => {
            let size = as_uint(value)?;
            Ok(ParameterValue::ImageSize(size))
        }
        SUIT_PARAMETER_URI => {
            let uri = as_tstr(value)?;
            Ok(ParameterValue::Uri(uri))
        }
        SUIT_PARAMETER_ENCRYPTION_INFO => {
            let bstr = as_bstr(value)?;
            Ok(ParameterValue::EncryptionInfo(bstr))
        }
        SUIT_PARAMETER_VERSION => {
            let bstr = as_bstr(value)?;
            let vm = decode_version_match(&bstr)?;
            Ok(ParameterValue::Version(vm))
        }
        SUIT_PARAMETER_SECURITY_VERSION => {
            let v = as_uint(value)?;
            Ok(ParameterValue::SecurityVersion(v))
        }
        _ => {
            // Unknown parameter — store raw bytes if bstr, or serialize
            match value {
                Value::Bytes(b) => Ok(ParameterValue::Raw(b.clone())),
                _ => {
                    let mut buf = Vec::new();
                    ciborium::ser::into_writer(value, &mut buf)
                        .map_err(|_| CodecError::CborDecode)?;
                    Ok(ParameterValue::Raw(buf))
                }
            }
        }
    }
}

// --- Digest ---

fn decode_digest_from_bstr(data: &[u8]) -> Result<DigestInfo, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;
    decode_digest(&value)
}

fn decode_digest(value: &Value) -> Result<DigestInfo, CodecError> {
    let arr = as_array(value)?;
    if arr.len() < 2 {
        return Err(CodecError::InvalidValue("digest array too short"));
    }

    let alg_id = as_int(&arr[0])?;
    let algorithm = match alg_id {
        -16 => DigestAlgorithm::Sha256,
        -43 => DigestAlgorithm::Sha384,
        -44 => DigestAlgorithm::Sha512,
        _ => return Err(CodecError::InvalidValue("unknown digest algorithm")),
    };

    let bytes = as_bstr(&arr[1])?;

    Ok(DigestInfo { algorithm, bytes })
}

// --- Version Match ---

fn decode_version_match(data: &[u8]) -> Result<VersionMatch, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;
    let arr = as_array(&value)?;
    if arr.len() < 2 {
        return Err(CodecError::InvalidValue("version match too short"));
    }

    let cmp_val = as_uint(&arr[0])? as u8;
    let comparison = match cmp_val {
        1 => VersionComparison::Greater,
        2 => VersionComparison::GreaterEqual,
        3 => VersionComparison::Equal,
        4 => VersionComparison::LesserEqual,
        5 => VersionComparison::Lesser,
        _ => return Err(CodecError::InvalidValue("unknown version comparison")),
    };

    let parts_arr = as_array(&arr[1])?;
    let mut parts = Vec::new();
    for p in parts_arr {
        parts.push(as_int(p)?);
    }

    Ok(VersionMatch { comparison, parts })
}

// --- Text ---

fn decode_text(data: &[u8]) -> Result<SuitText, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;
    let map = as_map(&value)?;

    let mut text = SuitText::default();

    for (k, v) in map {
        match k {
            // Integer key: manifest-level text
            Value::Integer(i) => {
                let label = i128::from(*i) as i64;
                if label == SUIT_TEXT_MANIFEST_DESCRIPTION {
                    text.description = Some(as_tstr(v)?);
                }
            }
            // Bytes key: per-component text (keyed by encoded component ID)
            Value::Bytes(_) => {
                if let Value::Map(comp_map) = v {
                    let tc = decode_text_component(comp_map)?;
                    // Use index based on order
                    text.components.insert(text.components.len(), tc);
                }
            }
            _ => {}
        }
    }

    Ok(text)
}

fn decode_text_component(map: &[(Value, Value)]) -> Result<TextComponent, CodecError> {
    let mut tc = TextComponent::default();
    for (k, v) in map {
        let label = as_int(k)?;
        let s = as_tstr(v)?;
        match label {
            1 => tc.vendor_name = Some(s),
            2 => tc.model_name = Some(s),
            3 => tc.vendor_domain = Some(s),
            4 => tc.model_info = Some(s),
            5 => tc.description = Some(s),
            6 => tc.version = Some(s),
            _ => {}
        }
    }
    Ok(tc)
}

// --- Component ID from CBOR ---

fn decode_component_id_from_cbor(data: &[u8]) -> Result<ComponentIdentifier, CodecError> {
    let value: Value = ciborium::de::from_reader(data).map_err(|_| CodecError::CborDecode)?;
    let arr = as_array(&value)?;
    let mut segments = Vec::new();
    for seg in arr {
        segments.push(as_bstr(seg)?);
    }
    Ok(ComponentIdentifier { segments })
}

// --- CBOR Value helpers ---

fn as_map(v: &Value) -> Result<&[(Value, Value)], CodecError> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(CodecError::InvalidValue("expected map")),
    }
}

fn as_array(v: &Value) -> Result<&[Value], CodecError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(CodecError::InvalidValue("expected array")),
    }
}

fn as_bstr(v: &Value) -> Result<Vec<u8>, CodecError> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(CodecError::InvalidValue("expected bstr")),
    }
}

fn as_tstr(v: &Value) -> Result<String, CodecError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(CodecError::InvalidValue("expected tstr")),
    }
}

fn as_uint(v: &Value) -> Result<u64, CodecError> {
    match v {
        Value::Integer(i) => {
            let val = i128::from(*i) as i64;
            if val >= 0 {
                Ok(val as u64)
            } else {
                Err(CodecError::InvalidValue("expected unsigned int"))
            }
        }
        _ => Err(CodecError::InvalidValue("expected uint")),
    }
}

fn as_int(v: &Value) -> Result<i64, CodecError> {
    match v {
        Value::Integer(i) => Ok(i128::from(*i) as i64),
        _ => Err(CodecError::InvalidValue("expected int")),
    }
}

fn uuid_from_bytes(bytes: &[u8]) -> Result<Uuid, CodecError> {
    if bytes.len() != 16 {
        return Err(CodecError::InvalidValue("UUID must be 16 bytes"));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(Uuid(arr))
}

// Map lookup helpers

fn get_from_map<'a>(map: &'a [(Value, Value)], key: i64) -> Result<&'a Value, CodecError> {
    for (k, v) in map {
        if let Value::Integer(i) = k {
            if i128::from(*i) as i64 == key {
                return Ok(v);
            }
        }
    }
    Err(CodecError::MissingField("map key"))
}

fn try_get_from_map<'a>(map: &'a [(Value, Value)], key: i64) -> Option<&'a Value> {
    for (k, v) in map {
        if let Value::Integer(i) = k {
            if i128::from(*i) as i64 == key {
                return Some(v);
            }
        }
    }
    None
}

fn get_bstr_from_map(map: &[(Value, Value)], key: i64) -> Result<Vec<u8>, CodecError> {
    let v = get_from_map(map, key)?;
    as_bstr(v)
}

fn try_get_bstr_from_map(map: &[(Value, Value)], key: i64) -> Option<Vec<u8>> {
    try_get_from_map(map, key).and_then(|v| as_bstr(v).ok())
}

fn try_get_bstr_by_key(map: &[(Value, Value)], key: i64) -> Option<Vec<u8>> {
    try_get_bstr_from_map(map, key)
}

fn get_uint_from_map(map: &[(Value, Value)], key: i64) -> Result<u64, CodecError> {
    let v = get_from_map(map, key)?;
    as_uint(v)
}

// Severed envelope keys
const SUIT_SEVERED_DEPENDENCY_RESOLUTION: i64 = 15;
const SUIT_SEVERED_PAYLOAD_FETCH: i64 = 16;
const SUIT_SEVERED_INSTALL: i64 = 20;
const SUIT_SEVERED_TEXT: i64 = 23;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_real_envelope() {
        // Real envelope generated by libcsuit/libsumo
        let hex = "a2025873825824822f58206ac0c1dfa2c11bc314999ecb38ea5c0553a6b5a45f5d2f8a6b4f8f3f07269d85584ad28443a10126a0f65840b1905327fff58efe11016c9dd79f5f9c7b90199cb7cc2c89d52fc24062f13e0ed5ab9b1a899637be38be2ffc84adbe2e411d45f3cb61b90842ce3375cb0e18ee035896a5010102182a035862a2028182426677436170700458548614a40150aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0250bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb035824822f582094d3b065150f3e618b865ebf56148ff163b04c7f674e29d4130390e26cf18fd00e14010f020f074382030f1458238613a1157819687474703a2f2f6578616d706c652e636f6d2f66772e62696e150f030f";
        let data = hex::decode(hex).unwrap();

        let env = decode_envelope(&data).unwrap();

        // Check manifest basics
        assert_eq!(env.manifest.manifest_version, 1);
        assert_eq!(env.manifest.sequence_number, 42);

        // Check components
        assert_eq!(env.manifest.common.components.len(), 1);
        let comp = &env.manifest.common.components[0];
        assert_eq!(comp.segments.len(), 2);
        assert_eq!(comp.segments[0], b"fw");
        assert_eq!(comp.segments[1], b"app");

        // Check shared sequence has override-parameters
        let shared = &env.manifest.common.shared_sequence;
        assert!(!shared.items.is_empty());

        // Check install sequence exists
        assert!(env.manifest.severable.install.is_some());

        // Check auth
        assert_eq!(env.authentication.digest.algorithm, DigestAlgorithm::Sha256);
        assert_eq!(env.authentication.signatures.len(), 1);

        // Check no integrated payloads
        assert!(env.integrated_payloads.is_empty());
    }

    #[test]
    fn decode_shared_sequence_params() {
        let hex = "a2025873825824822f58206ac0c1dfa2c11bc314999ecb38ea5c0553a6b5a45f5d2f8a6b4f8f3f07269d85584ad28443a10126a0f65840b1905327fff58efe11016c9dd79f5f9c7b90199cb7cc2c89d52fc24062f13e0ed5ab9b1a899637be38be2ffc84adbe2e411d45f3cb61b90842ce3375cb0e18ee035896a5010102182a035862a2028182426677436170700458548614a40150aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0250bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb035824822f582094d3b065150f3e618b865ebf56148ff163b04c7f674e29d4130390e26cf18fd00e14010f020f074382030f1458238613a1157819687474703a2f2f6578616d706c652e636f6d2f66772e62696e150f030f";
        let data = hex::decode(hex).unwrap();
        let env = decode_envelope(&data).unwrap();

        // Verify shared sequence parameters
        let shared = &env.manifest.common.shared_sequence;
        // First command should be override-parameters (label 20)
        assert_eq!(shared.items[0].label, 20); // SUIT_DIRECTIVE_OVERRIDE_PARAMETERS
        if let CommandValue::Parameters(ref params) = shared.items[0].value {
            // Should have vendor_id, class_id, image_digest, image_size
            assert!(params.len() >= 3);
            // Check vendor_id
            let vendor = params.iter().find(|p| p.label == 1).unwrap();
            if let ParameterValue::VendorId(ref uuid) = vendor.value {
                assert_eq!(uuid.0, [0xAA; 16]);
            } else {
                panic!("expected VendorId");
            }
        } else {
            panic!("expected Parameters");
        }

        // Install sequence: set-parameters with URI
        let install = env.manifest.severable.install.as_ref().unwrap();
        let set_params_cmd = install.items.iter()
            .find(|c| c.label == 19 || c.label == 20) // SET or OVERRIDE
            .unwrap();
        if let CommandValue::Parameters(ref params) = set_params_cmd.value {
            let uri = params.iter().find(|p| p.label == 21).unwrap();
            if let ParameterValue::Uri(ref u) = uri.value {
                assert_eq!(u, "http://example.com/fw.bin");
            } else {
                panic!("expected Uri");
            }
        } else {
            panic!("expected Parameters");
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let hex = "a2025873825824822f58206ac0c1dfa2c11bc314999ecb38ea5c0553a6b5a45f5d2f8a6b4f8f3f07269d85584ad28443a10126a0f65840b1905327fff58efe11016c9dd79f5f9c7b90199cb7cc2c89d52fc24062f13e0ed5ab9b1a899637be38be2ffc84adbe2e411d45f3cb61b90842ce3375cb0e18ee035896a5010102182a035862a2028182426677436170700458548614a40150aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0250bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb035824822f582094d3b065150f3e618b865ebf56148ff163b04c7f674e29d4130390e26cf18fd00e14010f020f074382030f1458238613a1157819687474703a2f2f6578616d706c652e636f6d2f66772e62696e150f030f";
        let data = hex::decode(hex).unwrap();

        // Decode
        let env = decode_envelope(&data).unwrap();

        // Re-encode (using same signature)
        let sig = env.authentication.signatures[0].clone();
        let encoded = crate::encode::encode_envelope(&env, |_manifest_bytes| {
            Ok(sig.clone())
        }).unwrap();

        // Decode the re-encoded envelope
        let env2 = decode_envelope(&encoded).unwrap();

        // Verify structural equivalence
        assert_eq!(env2.manifest.manifest_version, env.manifest.manifest_version);
        assert_eq!(env2.manifest.sequence_number, env.manifest.sequence_number);
        assert_eq!(env2.manifest.common.components.len(), env.manifest.common.components.len());
        assert_eq!(
            env2.manifest.common.components[0].segments,
            env.manifest.common.components[0].segments
        );
        assert_eq!(
            env2.manifest.common.shared_sequence.items.len(),
            env.manifest.common.shared_sequence.items.len()
        );
    }
}
