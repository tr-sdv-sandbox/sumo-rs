# sumo-rs — SUIT Manifest Library for Rust

Rust implementation of the [SUIT](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) (Software Updates for Internet of Things) manifest standard. Provides both server-side (offboard) manifest building and device-side (onboard) validation, decryption, and processing.

## Crates

| Crate | Purpose |
|-------|---------|
| **sumo-codec** | SUIT types, CBOR encode/decode, command sequences |
| **sumo-crypto** | Crypto traits + RustCrypto backend (AES-GCM, ECDH, SHA-256, HKDF) |
| **sumo-onboard** | Device-side: validator, streaming decryptor/decompressor, orchestrator, PlatformOps trait |
| **sumo-offboard** | Server-side: ImageManifestBuilder, CampaignBuilder, encryptor, keygen |
| **sumo-processor** | SUIT command sequence interpreter (abstract machine) |
| **sumo-tools** | CLI tool (`sumo-tool`) for keygen, build, inspect, campaign |

## Key Features

### Manifest Building (offboard)

```rust
let envelope = ImageManifestBuilder::new()
    .component_id(vec!["os1".into()])
    .sequence_number(1)
    .security_version(1)                    // Anti-rollback floor (custom param -257)
    .payload_digest(&digest, size)
    .payload_uri("#firmware".into())
    .integrated_payload("#firmware".into(), firmware)
    .encryption_info(&encrypted.encryption_info)
    .text_version("1.2.0")                  // Human-readable version
    .text_vendor_name("Acme Corp")
    .text_model_name("ECU-A Linux")
    .build(&signing_key)?;
```

### Manifest Validation (onboard)

```rust
let mut validator = Validator::new(&trust_anchor, None);
validator.add_device_key(&device_key)?;
let manifest = validator.validate_envelope(&envelope, &crypto, 0)?;

assert_eq!(manifest.text_version(0), Some("1.2.0"));
assert_eq!(manifest.security_version(0), Some(1));
assert!(manifest.has_install());
assert!(manifest.has_invoke());
```

### Encrypted Firmware

```rust
// Server: compress + encrypt
let compressed = encryptor::compress_firmware(&firmware, 3)?;
let encrypted = encryptor::encrypt_firmware_ecdh(&compressed, &sender_key, &recipients)?;

// Device: decrypt + decompress (streaming)
let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key, &crypto)?;
decryptor.update(&ciphertext, &mut plaintext)?;
decryptor.finalize(&mut plaintext)?;
```

### Campaign Manifests (L1 + L2)

```rust
let campaign = CampaignBuilder::new()
    .sequence_number(100)
    .add_integrated_image("l2-ecu-a".into(), &l2_a)
    .add_integrated_image("l2-ecu-b".into(), &l2_b)
    .build(&signing_key)?;
```

Campaign manifests generate proper SUIT command sequences:
- `dependency_resolution`: fetch L2 manifests
- `install`: process-dependency per ECU (all installed before any boots)
- `validate`: condition-dependency-integrity per ECU
- `invoke`: directive-invoke per ECU

### Security Version (Custom Parameter -257)

Separate from `sequence_number` (replay ordering). Enables A/B fleet testing:

```
v1.0.0 (seq=1, secver=1) ←→ v1.1.0 (seq=2, secver=1)   # freely interchangeable
v1.2.0 (seq=3, secver=2)                                   # security bump
CRL manifest (secver=2, no payload)                         # blocks secver < 2
```

After CRL: v1.0.0 and v1.1.0 permanently blocked. v1.2.0+ still works.

### SUIT Command Sequences

Manifests declare what the device should do via command sequences:

| Manifest type | install | validate | invoke | Flow |
|---|---|---|---|---|
| Firmware | directive-copy | condition-image-match | directive-invoke | Flash + verify + boot |
| CRL/policy | — | — | — | Apply security floor only |
| Config update | directive-write | condition-image-match | — | Write + verify, no reboot |

## Build & Test

```bash
cargo build
cargo test   # 29+ tests
```

## Standards

- [RFC 9124](https://datatracker.ietf.org/doc/rfc9124/) — SUIT Information Model
- [draft-ietf-suit-manifest-34](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/) — SUIT Manifest Format
- [draft-ietf-suit-firmware-encryption](https://datatracker.ietf.org/doc/draft-ietf-suit-firmware-encryption/) — Firmware Encryption
- [draft-ietf-suit-update-management](https://datatracker.ietf.org/doc/draft-ietf-suit-update-management/) — Version Matching Extensions

## Related Projects

- [sumo-sovd](https://github.com/sdv-playground/sumo-sovd) — Campaign orchestrator over SOVD
- [vm-mgr](https://github.com/sdv-playground/vm-mgr) — VM lifecycle manager with SUIT integration
- [SOVDd](https://github.com/sdv-playground/SOVDd) — SOVD diagnostic server
- [SUMO specs](https://github.com/tr-sdv-sandbox/sumo) — Specifications and feature mapping
