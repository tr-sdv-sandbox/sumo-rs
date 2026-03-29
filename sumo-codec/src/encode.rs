//! SUIT envelope encoding to CBOR bytes.

use ciborium::value::{Integer, Value};

use crate::commands::{CommandItem, CommandSequence, CommandValue};
use crate::envelope::SuitEnvelope;
use crate::error::CodecError;
use crate::labels::*;
use crate::manifest::{SuitCommon, SuitManifest};
use crate::parameters::{ParameterValue, SuitParameter};
use crate::text::{SuitText, TextComponent};
use crate::types::{DigestAlgorithm, DigestInfo, VersionMatch};

/// Encode a SUIT envelope to CBOR bytes.
///
/// The `sign_fn` callback receives the serialized manifest CBOR and must return
/// a COSE_Sign1 signature (raw CBOR bytes).
pub fn encode_envelope<F>(
    envelope: &SuitEnvelope,
    sign_fn: F,
) -> Result<Vec<u8>, CodecError>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, CodecError>,
{
    // 1. Encode manifest to CBOR bytes
    let manifest_bytes = encode_manifest(&envelope.manifest)?;

    // 2. Compute digest of manifest bytes (caller provides this in envelope.authentication)
    // 3. Sign manifest bytes
    let signature = sign_fn(&manifest_bytes)?;

    // 4. Build authentication wrapper: [ bstr(digest), bstr(signature) ]
    let digest_cbor = encode_digest(&envelope.authentication.digest)?;
    let auth_array = Value::Array(vec![
        Value::Bytes(digest_cbor),
        Value::Bytes(signature),
    ]);
    let auth_bytes = cbor_serialize(&auth_array)?;

    // 5. Build envelope map
    let mut entries: Vec<(Value, Value)> = Vec::new();

    // Key 2: authentication wrapper
    entries.push((int_key(SUIT_AUTHENTICATION_WRAPPER), Value::Bytes(auth_bytes)));

    // Key 3: manifest
    entries.push((int_key(SUIT_MANIFEST), Value::Bytes(manifest_bytes)));

    // Severed members at envelope level (keys 15, 16, 20, 23)
    if let Some(ref dep_res) = envelope.manifest.severable.dependency_resolution {
        let bstr = encode_command_sequence(dep_res)?;
        entries.push((int_key(15), Value::Bytes(bstr)));
    }
    if let Some(ref pf) = envelope.manifest.severable.payload_fetch {
        let bstr = encode_command_sequence(pf)?;
        entries.push((int_key(16), Value::Bytes(bstr)));
    }
    if let Some(ref install) = envelope.manifest.severable.install {
        let bstr = encode_command_sequence(install)?;
        entries.push((int_key(20), Value::Bytes(bstr)));
    }
    if let Some(ref text) = envelope.manifest.severable.text {
        let bstr = encode_text(text)?;
        entries.push((int_key(23), Value::Bytes(bstr)));
    }

    // Integrated payloads (text string keys)
    for (key, payload) in &envelope.integrated_payloads {
        entries.push((Value::Text(key.clone()), Value::Bytes(payload.clone())));
    }

    let envelope_map = Value::Map(entries);
    cbor_serialize(&envelope_map)
}

/// Encode just the manifest portion (without envelope wrapper).
/// Used internally and for computing the manifest digest.
pub fn encode_manifest(manifest: &SuitManifest) -> Result<Vec<u8>, CodecError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();

    // Key 1: manifest version
    entries.push((int_key(SUIT_MANIFEST_VERSION), Value::Integer(Integer::from(manifest.manifest_version as i64))));

    // Key 2: sequence number
    entries.push((int_key(SUIT_MANIFEST_SEQUENCE_NUMBER), Value::Integer(Integer::from(manifest.sequence_number as i64))));

    // Key 3: common (bstr-wrapped)
    let common_bytes = encode_common(&manifest.common)?;
    entries.push((int_key(SUIT_COMMON), Value::Bytes(common_bytes)));

    // Key 7: validate (optional, bstr-wrapped command sequence)
    if let Some(ref validate) = manifest.validate {
        let bstr = encode_command_sequence(validate)?;
        entries.push((int_key(SUIT_VALIDATE), Value::Bytes(bstr)));
    }

    // Key 9: invoke (optional)
    if let Some(ref invoke) = manifest.invoke {
        let bstr = encode_command_sequence(invoke)?;
        entries.push((int_key(SUIT_INVOKE), Value::Bytes(bstr)));
    }

    // Severable members as digest or inline
    // For now, encode inline references (the actual content goes at envelope level)
    // Key 15: dependency-resolution
    if manifest.severable.dependency_resolution.is_some() {
        // Encode as digest placeholder — the actual sequence goes at envelope level
        // For simplicity, we just omit here (encoder puts at envelope level)
    }

    // Key 20: install
    if let Some(ref install) = manifest.severable.install {
        let bstr = encode_command_sequence(install)?;
        entries.push((int_key(SUIT_INSTALL), Value::Bytes(bstr)));
    }

    let manifest_map = Value::Map(entries);
    cbor_serialize(&manifest_map)
}

// --- Common ---

fn encode_common(common: &SuitCommon) -> Result<Vec<u8>, CodecError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();

    // Key 1: dependencies (if any)
    if !common.dependencies.is_empty() {
        let mut dep_entries: Vec<(Value, Value)> = Vec::new();
        for dep in &common.dependencies {
            let mut meta_entries: Vec<(Value, Value)> = Vec::new();
            if let Some(ref prefix) = dep.prefix {
                let prefix_cbor = encode_component_id(prefix)?;
                meta_entries.push((int_key(SUIT_DEPENDENCY_PREFIX), Value::Bytes(prefix_cbor)));
            }
            dep_entries.push((
                Value::Integer(Integer::from(dep.index as i64)),
                Value::Map(meta_entries),
            ));
        }
        entries.push((int_key(SUIT_DEPENDENCIES), Value::Map(dep_entries)));
    }

    // Key 2: components
    if !common.components.is_empty() {
        let comps: Vec<Value> = common
            .components
            .iter()
            .map(|c| {
                Value::Array(c.segments.iter().map(|s| Value::Bytes(s.clone())).collect())
            })
            .collect();
        entries.push((int_key(SUIT_COMPONENTS), Value::Array(comps)));
    }

    // Key 4: shared sequence (bstr-wrapped)
    if !common.shared_sequence.items.is_empty() {
        let bstr = encode_command_sequence(&common.shared_sequence)?;
        entries.push((int_key(SUIT_SHARED_SEQUENCE), Value::Bytes(bstr)));
    }

    let map = Value::Map(entries);
    cbor_serialize(&map)
}

// --- Command Sequence ---

fn encode_command_sequence(seq: &CommandSequence) -> Result<Vec<u8>, CodecError> {
    let mut flat: Vec<Value> = Vec::new();
    for item in &seq.items {
        encode_command_item(item, &mut flat)?;
    }
    let arr = Value::Array(flat);
    cbor_serialize(&arr)
}

fn encode_command_item(item: &CommandItem, out: &mut Vec<Value>) -> Result<(), CodecError> {
    out.push(Value::Integer(Integer::from(item.label)));

    match &item.value {
        CommandValue::ComponentIndex(idx) => {
            out.push(Value::Integer(Integer::from(*idx as i64)));
        }
        CommandValue::Parameters(params) => {
            let param_map = encode_parameters(params)?;
            out.push(param_map);
        }
        CommandValue::ReportingPolicy(rp) => {
            out.push(Value::Integer(Integer::from(*rp as i64)));
        }
    }

    Ok(())
}

// --- Parameters ---

fn encode_parameters(params: &[SuitParameter]) -> Result<Value, CodecError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    for p in params {
        let val = encode_parameter_value(&p.value)?;
        entries.push((int_key(p.label), val));
    }
    Ok(Value::Map(entries))
}

fn encode_parameter_value(value: &ParameterValue) -> Result<Value, CodecError> {
    match value {
        ParameterValue::VendorId(uuid) => Ok(Value::Bytes(uuid.0.to_vec())),
        ParameterValue::ClassId(uuid) => Ok(Value::Bytes(uuid.0.to_vec())),
        ParameterValue::DeviceId(uuid) => Ok(Value::Bytes(uuid.0.to_vec())),
        ParameterValue::ImageDigest(digest) => {
            let cbor = encode_digest(digest)?;
            Ok(Value::Bytes(cbor))
        }
        ParameterValue::ImageSize(size) => {
            Ok(Value::Integer(Integer::from(*size as i64)))
        }
        ParameterValue::Uri(uri) => Ok(Value::Text(uri.clone())),
        ParameterValue::EncryptionInfo(info) => Ok(Value::Bytes(info.clone())),
        ParameterValue::Version(vm) => {
            let cbor = encode_version_match(vm)?;
            Ok(Value::Bytes(cbor))
        }
        ParameterValue::SecurityVersion(v) => Ok(Value::Integer(Integer::from(*v))),
        ParameterValue::Raw(raw) => Ok(Value::Bytes(raw.clone())),
    }
}

// --- Digest ---

fn encode_digest(digest: &DigestInfo) -> Result<Vec<u8>, CodecError> {
    let alg = match digest.algorithm {
        DigestAlgorithm::Sha256 => -16i64,
        DigestAlgorithm::Sha384 => -43,
        DigestAlgorithm::Sha512 => -44,
    };
    let arr = Value::Array(vec![
        Value::Integer(Integer::from(alg)),
        Value::Bytes(digest.bytes.clone()),
    ]);
    cbor_serialize(&arr)
}

// --- Version Match ---

fn encode_version_match(vm: &VersionMatch) -> Result<Vec<u8>, CodecError> {
    use crate::types::VersionComparison;
    let cmp_val = match vm.comparison {
        VersionComparison::Greater => 1i64,
        VersionComparison::GreaterEqual => 2,
        VersionComparison::Equal => 3,
        VersionComparison::LesserEqual => 4,
        VersionComparison::Lesser => 5,
    };
    let parts: Vec<Value> = vm.parts.iter().map(|p| Value::Integer(Integer::from(*p))).collect();
    let arr = Value::Array(vec![
        Value::Integer(Integer::from(cmp_val)),
        Value::Array(parts),
    ]);
    cbor_serialize(&arr)
}

// --- Text ---

fn encode_text(text: &SuitText) -> Result<Vec<u8>, CodecError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();

    if let Some(ref desc) = text.description {
        entries.push((int_key(SUIT_TEXT_MANIFEST_DESCRIPTION), Value::Text(desc.clone())));
    }

    for (_idx, tc) in &text.components {
        let tc_val = encode_text_component(tc)?;
        // TODO: encode component identifier as bstr key
        entries.push((Value::Bytes(Vec::new()), tc_val));
    }

    let map = Value::Map(entries);
    cbor_serialize(&map)
}

fn encode_text_component(tc: &TextComponent) -> Result<Value, CodecError> {
    let mut entries: Vec<(Value, Value)> = Vec::new();
    if let Some(ref s) = tc.vendor_name { entries.push((int_key(1), Value::Text(s.clone()))); }
    if let Some(ref s) = tc.model_name { entries.push((int_key(2), Value::Text(s.clone()))); }
    if let Some(ref s) = tc.vendor_domain { entries.push((int_key(3), Value::Text(s.clone()))); }
    if let Some(ref s) = tc.model_info { entries.push((int_key(4), Value::Text(s.clone()))); }
    if let Some(ref s) = tc.description { entries.push((int_key(5), Value::Text(s.clone()))); }
    if let Some(ref s) = tc.version { entries.push((int_key(6), Value::Text(s.clone()))); }
    Ok(Value::Map(entries))
}

// --- Component ID encoding ---

fn encode_component_id(comp: &crate::component::ComponentIdentifier) -> Result<Vec<u8>, CodecError> {
    let arr = Value::Array(
        comp.segments.iter().map(|s| Value::Bytes(s.clone())).collect(),
    );
    cbor_serialize(&arr)
}

// --- Helpers ---

fn int_key(k: i64) -> Value {
    Value::Integer(Integer::from(k))
}

fn cbor_serialize(value: &Value) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|_| CodecError::CborEncode)?;
    Ok(buf)
}
