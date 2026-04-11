//! YAML-driven manifest descriptor for `sumo-tool build --manifest`.
//!
//! Defines a declarative YAML schema that maps to `ImageManifestBuilder` calls.
//! Supports all manifest patterns: full build, reference build, and CRL/policy-only.

use std::path::PathBuf;

use serde::Deserialize;

/// Top-level YAML manifest descriptor.
///
/// Two modes:
/// - **Single component**: uses `component_id` + `payload` (existing, backward compatible)
/// - **Multi component**: uses `components` array (new, for kernel + rootfs)
#[derive(Debug, Deserialize)]
pub struct ManifestDescriptor {
    /// Component ID segments (single-component mode).
    #[serde(default)]
    pub component_id: Option<ComponentId>,

    /// Monotonically increasing sequence number.
    pub sequence_number: u64,

    /// Anti-rollback security version (separate from sequence_number).
    #[serde(default)]
    pub security_version: Option<u64>,

    /// Path to the signing key file (COSE_Key CBOR).
    pub signing_key: PathBuf,

    /// Payload configuration (single-component mode).
    #[serde(default)]
    pub payload: Option<PayloadDescriptor>,

    /// Multi-component mode: array of component specs.
    /// When present, `component_id` and `payload` are ignored.
    #[serde(default)]
    pub components: Option<Vec<ComponentDescriptor>>,

    /// Output paths.
    pub output: OutputDescriptor,

    /// Human-readable metadata.
    #[serde(default)]
    pub metadata: Option<MetadataDescriptor>,
}

impl ManifestDescriptor {
    /// Check if this is a multi-component manifest.
    pub fn is_multi_component(&self) -> bool {
        self.components.as_ref().map_or(false, |c| !c.is_empty())
    }
}

/// A single component in a multi-component manifest.
#[derive(Debug, Deserialize)]
pub struct ComponentDescriptor {
    /// Component ID segments (e.g., `["os1", "kernel"]`).
    pub id: ComponentId,

    /// Payload configuration for this component.
    pub payload: PayloadDescriptor,
}

/// Component ID: accepts both `"os1"` (single string) and `["hsm", "keys"]` (list).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ComponentId {
    Single(String),
    Multi(Vec<String>),
}

impl ComponentId {
    pub fn to_vec(&self) -> Vec<String> {
        match self {
            ComponentId::Single(s) => s.split(',').map(|s| s.to_string()).collect(),
            ComponentId::Multi(v) => v.clone(),
        }
    }
}

/// Payload section — mutually exclusive modes:
///
/// - **Full build**: `file` is set (path or `"-"` for stdin)
/// - **Reference build**: `digest` + `size` are set (no file)
/// - **Absent**: no payload section at all → CRL/policy-only manifest
#[derive(Debug, Deserialize)]
pub struct PayloadDescriptor {
    /// Path to firmware/payload file, or `"-"` for stdin.
    #[serde(default)]
    pub file: Option<String>,

    /// Fetch URI or integrated payload key (e.g., `"#firmware"`, `"#hsm-keys"`).
    #[serde(default)]
    pub uri: Option<String>,

    /// Enable zstd compression before encryption.
    #[serde(default)]
    pub compress: bool,

    /// Encryption configuration.
    #[serde(default)]
    pub encrypt: Option<EncryptDescriptor>,

    // --- Reference mode fields (mutually exclusive with `file`) ---

    /// Pre-computed SHA-256 digest (hex string, 64 chars).
    #[serde(default)]
    pub digest: Option<String>,

    /// Payload size in bytes.
    #[serde(default)]
    pub size: Option<u64>,

    /// Path to encryption_info CBOR file (from a prior build with separate payload output).
    #[serde(default)]
    pub encryption_info: Option<PathBuf>,
}

/// Encryption configuration.
#[derive(Debug, Deserialize)]
pub struct EncryptDescriptor {
    /// Device key file paths. Key type auto-detected: EC2 → ECDH-ES+A128KW, symmetric → A128KW.
    pub device_keys: Vec<PathBuf>,
}

/// Output paths.
#[derive(Debug, Deserialize)]
pub struct OutputDescriptor {
    /// Path for the signed SUIT envelope.
    pub manifest: PathBuf,

    /// Path for separate (non-integrated) encrypted payload (single-component mode).
    /// If omitted, payload is integrated into the envelope.
    #[serde(default)]
    pub payload: Option<PathBuf>,

    /// Paths for separate payloads (multi-component mode).
    /// Keys match the component URIs (e.g., `"#kernel"`, `"#firmware"`).
    #[serde(default)]
    pub payloads: Option<std::collections::HashMap<String, PathBuf>>,
}

/// Human-readable metadata fields (all optional).
#[derive(Debug, Deserialize)]
pub struct MetadataDescriptor {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub model_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub vendor_name: Option<String>,
    #[serde(default)]
    pub model_info: Option<String>,
    #[serde(default)]
    pub vendor_id: Option<String>,
    #[serde(default)]
    pub class_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_manifest() {
        let yaml = r##"
component_id: ["os1"]
sequence_number: 2
security_version: 1
signing_key: keys/signing.key

payload:
  file: firmware/rootfs.img
  uri: "#firmware"
  compress: true
  encrypt:
    device_keys: ["keys/device.pub"]

output:
  manifest: os1-v1.1.0.suit
  payload: firmware/payload.bin

metadata:
  version: "1.1.0"
  model_name: "OS1-Linux"
  description: "OS1 rootfs update v1.1.0"
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(desc.component_id.as_ref().unwrap().to_vec(), vec!["os1"]);
        assert_eq!(desc.sequence_number, 2);
        assert_eq!(desc.security_version, Some(1));

        let payload = desc.payload.unwrap();
        assert_eq!(payload.file.as_deref(), Some("firmware/rootfs.img"));
        assert_eq!(payload.uri.as_deref(), Some("#firmware"));
        assert!(payload.compress);
        assert_eq!(payload.encrypt.unwrap().device_keys.len(), 1);

        assert_eq!(desc.output.manifest, PathBuf::from("os1-v1.1.0.suit"));
        assert_eq!(desc.output.payload, Some(PathBuf::from("firmware/payload.bin")));

        let meta = desc.metadata.unwrap();
        assert_eq!(meta.version.as_deref(), Some("1.1.0"));
        assert_eq!(meta.model_name.as_deref(), Some("OS1-Linux"));
    }

    #[test]
    fn parse_reference_manifest() {
        let yaml = r##"
component_id: "os1"
sequence_number: 3
security_version: 1
signing_key: keys/signing.key

payload:
  digest: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
  size: 512000000
  encryption_info: payload.bin.enc-info
  uri: "#firmware"

output:
  manifest: os1-v1.2.0.suit

metadata:
  version: "1.2.0"
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(desc.component_id.as_ref().unwrap().to_vec(), vec!["os1"]);
        assert_eq!(desc.sequence_number, 3);

        let payload = desc.payload.unwrap();
        assert!(payload.file.is_none());
        assert!(payload.digest.is_some());
        assert_eq!(payload.size, Some(512000000));
        assert_eq!(payload.encryption_info, Some(PathBuf::from("payload.bin.enc-info")));

        assert!(desc.output.payload.is_none());
    }

    #[test]
    fn parse_crl_manifest() {
        let yaml = r##"
component_id: "os1"
sequence_number: 100
security_version: 2
signing_key: keys/signing.key

output:
  manifest: os1-crl.suit

metadata:
  description: "CRL: block security_version < 2"
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(desc.component_id.as_ref().unwrap().to_vec(), vec!["os1"]);
        assert_eq!(desc.sequence_number, 100);
        assert_eq!(desc.security_version, Some(2));
        assert!(desc.payload.is_none());
    }

    #[test]
    fn parse_multi_segment_component_id() {
        let yaml = r##"
component_id: ["hsm", "keys"]
sequence_number: 1
signing_key: keys/signing.key
output:
  manifest: hsm-keys.suit
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(desc.component_id.as_ref().unwrap().to_vec(), vec!["hsm", "keys"]);
    }

    #[test]
    fn parse_single_string_component_id() {
        let yaml = r##"
component_id: os1
sequence_number: 1
signing_key: k
output:
  manifest: out.suit
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(desc.component_id.as_ref().unwrap().to_vec(), vec!["os1"]);
    }

    #[test]
    fn parse_stdin_payload() {
        let yaml = r##"
component_id: ["hsm", "keys"]
sequence_number: 1
signing_key: keys/signing.key
payload:
  file: "-"
  uri: "#hsm-keys"
  compress: true
  encrypt:
    device_keys: ["keys/device.pub"]
output:
  manifest: hsm-keys-v1.suit
metadata:
  version: "1.0.0"
  vendor_name: "vm-mgr"
  model_name: "HSM-Keys"
  description: "Factory HSM key provisioning"
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        let payload = desc.payload.unwrap();
        assert_eq!(payload.file.as_deref(), Some("-"));
        assert_eq!(payload.uri.as_deref(), Some("#hsm-keys"));
        assert!(payload.compress);
    }

    #[test]
    fn parse_minimal_metadata() {
        let yaml = r##"
component_id: os1
sequence_number: 1
signing_key: k
output:
  manifest: out.suit
metadata:
  vendor_id: "fa6b4a53d5ad5fdfbe9de4e97d85cd2b"
  class_id: "1492af1425695e48bf429b2d51f2ab45"
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        let meta = desc.metadata.unwrap();
        assert_eq!(meta.vendor_id.as_deref(), Some("fa6b4a53d5ad5fdfbe9de4e97d85cd2b"));
        assert_eq!(meta.class_id.as_deref(), Some("1492af1425695e48bf429b2d51f2ab45"));
    }

    #[test]
    fn parse_multi_component_manifest() {
        let yaml = r##"
sequence_number: 1
security_version: 1
signing_key: keys/signing.key

components:
  - id: ["os1", "kernel"]
    payload:
      file: firmware/bzImage
      uri: "#kernel"
      compress: true
      encrypt:
        device_keys: ["keys/device.key"]
  - id: ["os1", "rootfs"]
    payload:
      file: firmware/rootfs.img
      uri: "#firmware"
      compress: true
      encrypt:
        device_keys: ["keys/device.key"]

output:
  manifest: os1-v1.0.0.suit
  payloads:
    "#kernel": firmware/kernel-payload.bin
    "#firmware": firmware/rootfs-payload.bin

metadata:
  version: "1.0.0"
  model_name: "OS1-Linux"
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert!(desc.is_multi_component());
        assert!(desc.component_id.is_none());
        assert!(desc.payload.is_none());

        let components = desc.components.unwrap();
        assert_eq!(components.len(), 2);
        assert_eq!(components[0].id.to_vec(), vec!["os1", "kernel"]);
        assert_eq!(components[0].payload.uri.as_deref(), Some("#kernel"));
        assert_eq!(components[1].id.to_vec(), vec!["os1", "rootfs"]);
        assert_eq!(components[1].payload.uri.as_deref(), Some("#firmware"));

        let payloads = desc.output.payloads.unwrap();
        assert_eq!(payloads.len(), 2);
        assert!(payloads.contains_key("#kernel"));
        assert!(payloads.contains_key("#firmware"));
    }

    #[test]
    fn parse_multi_component_reference() {
        let yaml = r##"
sequence_number: 2
security_version: 1
signing_key: keys/signing.key

components:
  - id: ["os1", "kernel"]
    payload:
      digest: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
      size: 10000000
      encryption_info: firmware/kernel-payload.bin.enc-info
      uri: "#kernel"
  - id: ["os1", "rootfs"]
    payload:
      digest: "11223344556677881122334455667788112233445566778811223344556677aa"
      size: 2147483648
      encryption_info: firmware/rootfs-payload.bin.enc-info
      uri: "#firmware"

output:
  manifest: os1-v1.1.0.suit
"##;
        let desc: ManifestDescriptor = serde_yaml::from_str(yaml).unwrap();
        assert!(desc.is_multi_component());
        let components = desc.components.unwrap();
        assert!(components[0].payload.file.is_none());
        assert!(components[0].payload.digest.is_some());
        assert!(components[1].payload.digest.is_some());
    }
}
