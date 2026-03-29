# CLAUDE.md — sumo-rs

## Project Overview

Rust implementation of the SUIT (Software Updates for IoT) manifest
standard. Provides both server-side (offboard) manifest building and
device-side (onboard) validation, decryption, and processing.

### Crate Architecture

```
sumo-codec          SUIT types, CBOR encode/decode, command sequences
  ↓
sumo-crypto         Crypto traits + RustCrypto backend
  ↓
sumo-onboard        Validator, StreamingDecryptor, StreamingDecompressor,
                    PlatformOps trait, orchestrator, policy
  ↓
sumo-processor      SUIT command sequence interpreter (abstract machine)
  ↓
sumo-offboard       ImageManifestBuilder, CampaignBuilder, encryptor, keygen
  ↓
sumo-tools          CLI tool (sumo-tool): keygen, build, inspect, campaign
```

### Key Design Decisions

- **Security version (custom param -257)**: Separate from sequence_number.
  sequence_number is for replay ordering; security_version is the anti-rollback
  floor that only advances on explicit commit. Enables A/B fleet testing.

- **SUIT command sequences**: Manifests declare the update flow. Firmware
  manifests include install (directive-copy) + validate (condition-image-match)
  + invoke (directive-invoke). CRL manifests have none — just parameters.

- **Two-level manifests**: L1 campaign (process-dependency per ECU with
  staged install → validate → invoke) + L2 image (per-ECU firmware).

- **Streaming crypto**: Decryption and decompression are streaming to support
  constrained devices. The orchestrator processes payloads in 4KB chunks.

- **no_std support**: sumo-codec, sumo-crypto, sumo-onboard work without std
  (with alloc). PlatformOps abstracts all I/O.

### Key Files

```
sumo-codec/src/
  labels.rs             — SUIT CBOR integer constants (incl. custom -257)
  parameters.rs         — ParameterValue enum (incl. SecurityVersion)
  commands.rs           — CommandSequence, CommandItem, CommandValue
  text.rs               — SuitText, TextComponent
  encode.rs / decode.rs — CBOR serialization

sumo-onboard/src/
  validator.rs          — Envelope validation (signature, digest, rollback)
  manifest.rs           — Accessor methods (has_install, has_invoke, security_version, text_*)
  orchestrator.rs       — L2 payload processing (fetch, decrypt, decompress, verify, write)
  platform.rs           — PlatformOps + StorageOps traits
  decryptor.rs          — Streaming AES-GCM (A128KW + ECDH-ES+A128KW)
  decompressor.rs       — Streaming zstd

sumo-offboard/src/
  image_builder.rs      — ImageManifestBuilder (fluent API, text fields, security_version)
  campaign_builder.rs   — CampaignBuilder (staged install/validate/invoke sequences)
  encryptor.rs          — compress_firmware, encrypt_firmware, encrypt_firmware_ecdh
  keygen.rs             — generate_signing_key, generate_device_key

sumo-processor/src/
  processor.rs          — SuitProcessor: walks sequences, dispatches to PlatformOps
```

## Build & Test

```bash
cargo build
cargo test    # 29+ tests (codec, crypto, e2e roundtrips)
```

## Workflow

Use typed enums from sumo-codec, not raw strings.
Custom SUIT parameters use negative integer labels (private use range).
