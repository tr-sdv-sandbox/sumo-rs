//! End-to-end tests for the full SUIT pipeline:
//! keygen → encrypt → build manifest → validate → decrypt → verify

use std::cell::RefCell;
use std::collections::HashMap;

use sumo_codec::types::Uuid;
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::image_builder::ImageManifestBuilder;
use sumo_offboard::campaign_builder::CampaignBuilder;
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;
use sumo_onboard::decryptor::StreamingDecryptor;
use sumo_onboard::decompressor::StreamingDecompressor;
use sumo_onboard::error::Sum2Error;
use sumo_onboard::orchestrator;
use sumo_onboard::platform::{PlatformOps, StorageOps};
use sumo_onboard::policy;
use sumo_onboard::validator::Validator;

// --- Test constants ---

const VENDOR_UUID: [u8; 16] = [0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF,
                                 0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE];
const CLASS_UUID: [u8; 16] =  [0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48,
                                 0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45];

// --- Test helpers ---

fn test_vendor() -> Uuid { Uuid(VENDOR_UUID) }
fn test_class() -> Uuid { Uuid(CLASS_UUID) }

fn generate_a128kw_key(kid: &[u8]) -> CoseKey {
    let crypto = RustCryptoBackend::new();
    let mut key_bytes = [0u8; 16];
    crypto.random_bytes(&mut key_bytes).unwrap();

    // Build symmetric COSE_Key
    let inner = coset::CoseKeyBuilder::new_symmetric_key(key_bytes.to_vec())
        .key_id(kid.to_vec())
        .algorithm(coset::iana::Algorithm::A128KW)
        .build();
    CoseKey::from_cose_key_bytes(&inner.to_vec().unwrap()).unwrap()
}

fn build_test_image(
    firmware: &[u8],
    signing_key: &CoseKey,
    recipients: &[Recipient],
    compress: bool,
) -> (Vec<u8>, Vec<u8>) {
    // Optionally compress
    let payload = if compress {
        encryptor::compress_firmware(firmware, 3).unwrap()
    } else {
        firmware.to_vec()
    };

    // Encrypt
    let encrypted = encryptor::encrypt_firmware(&payload, recipients).unwrap();

    // Build manifest with digest of *original plaintext* (pre-encryption, post-compression if compressed)
    let digest = if compress {
        // Digest is of the *plaintext* (before compression) for the orchestrator
        // Actually no: digest should be of the *original* firmware
        encryptor::sha256(firmware)
    } else {
        encryptor::sha256(firmware)
    };

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["ecu-a".into(), "firmware".into()])
        .sequence_number(42)
        .vendor_id(test_vendor())
        .class_id(test_class())
        .payload_digest(&digest, firmware.len() as u64)
        .payload_uri("https://fw.example.com/ecu-a.enc".into())
        .encryption_info(&encrypted.encryption_info)
        .build(signing_key)
        .unwrap();

    (envelope, encrypted.ciphertext)
}

fn build_test_image_ecdh(
    firmware: &[u8],
    signing_key: &CoseKey,
    sender_key: &CoseKey,
    recipients: &[Recipient],
) -> (Vec<u8>, Vec<u8>) {
    let encrypted = encryptor::encrypt_firmware_ecdh(firmware, sender_key, recipients).unwrap();

    let digest = encryptor::sha256(firmware);

    let envelope = ImageManifestBuilder::new()
        .component_id(vec!["ecu-a".into(), "firmware".into()])
        .sequence_number(42)
        .vendor_id(test_vendor())
        .class_id(test_class())
        .payload_digest(&digest, firmware.len() as u64)
        .payload_uri("https://fw.example.com/ecu-a.enc".into())
        .encryption_info(&encrypted.encryption_info)
        .build(signing_key)
        .unwrap();

    (envelope, encrypted.ciphertext)
}

// --- Fake platform ops ---

struct FakePlatformOps {
    fetch_store: RefCell<HashMap<String, Vec<u8>>>,
    written: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    persisted_seqs: RefCell<HashMap<Vec<u8>, u64>>,
}

impl FakePlatformOps {
    fn new() -> Self {
        Self {
            fetch_store: RefCell::new(HashMap::new()),
            written: RefCell::new(HashMap::new()),
            persisted_seqs: RefCell::new(HashMap::new()),
        }
    }

    fn add_fetch(&self, uri: &str, data: Vec<u8>) {
        self.fetch_store.borrow_mut().insert(uri.to_string(), data);
    }

    fn get_written(&self, comp_id: &[u8]) -> Vec<u8> {
        self.written.borrow().get(comp_id).cloned().unwrap_or_default()
    }
}

impl PlatformOps for FakePlatformOps {
    fn fetch(&self, uri: &str, buf: &mut [u8]) -> Result<usize, Sum2Error> {
        let store = self.fetch_store.borrow();
        let data = store.get(uri).ok_or(Sum2Error::CallbackFailed)?;
        let len = std::cmp::min(data.len(), buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok(len)
    }

    fn write(&self, component_id: &[u8], offset: usize, data: &[u8]) -> Result<(), Sum2Error> {
        let mut written = self.written.borrow_mut();
        let entry = written.entry(component_id.to_vec()).or_default();
        if offset + data.len() > entry.len() {
            entry.resize(offset + data.len(), 0);
        }
        entry[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn invoke(&self, _component_id: &[u8]) -> Result<(), Sum2Error> {
        Ok(())
    }

    fn swap(&self, _comp_a: &[u8], _comp_b: &[u8]) -> Result<(), Sum2Error> {
        Ok(())
    }

    fn persist_sequence(&self, component_id: &[u8], seq: u64) -> Result<(), Sum2Error> {
        self.persisted_seqs.borrow_mut().insert(component_id.to_vec(), seq);
        Ok(())
    }
}

struct FakeStorageOps {
    u64s: RefCell<HashMap<String, u64>>,
    i64s: RefCell<HashMap<String, i64>>,
}

impl FakeStorageOps {
    fn new() -> Self {
        Self {
            u64s: RefCell::new(HashMap::new()),
            i64s: RefCell::new(HashMap::new()),
        }
    }
}

impl StorageOps for FakeStorageOps {
    fn read_u64(&self, key: &str) -> Result<u64, Sum2Error> {
        self.u64s.borrow().get(key).copied().ok_or(Sum2Error::CallbackFailed)
    }
    fn write_u64(&self, key: &str, value: u64) -> Result<(), Sum2Error> {
        self.u64s.borrow_mut().insert(key.to_string(), value);
        Ok(())
    }
    fn read_i64(&self, key: &str) -> Result<i64, Sum2Error> {
        self.i64s.borrow().get(key).copied().ok_or(Sum2Error::CallbackFailed)
    }
    fn write_i64(&self, key: &str, value: i64) -> Result<(), Sum2Error> {
        self.i64s.borrow_mut().insert(key.to_string(), value);
        Ok(())
    }
}

// ============================================================
// Tests
// ============================================================

#[test]
fn keygen_es256_roundtrip() {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let cbor = keygen::serialize_key(&key, true).unwrap();
    let restored = CoseKey::from_cose_key_bytes(&cbor).unwrap();
    assert!(!restored.public_key_bytes().is_empty());

    let pub_cbor = keygen::serialize_key(&key, false).unwrap();
    assert!(pub_cbor.len() < cbor.len()); // public key is smaller
}

#[test]
fn keygen_eddsa_roundtrip() {
    let key = keygen::generate_signing_key(keygen::EDDSA).unwrap();
    let cbor = keygen::serialize_key(&key, true).unwrap();
    let restored = CoseKey::from_cose_key_bytes(&cbor).unwrap();
    assert!(!restored.public_key_bytes().is_empty());
}

#[test]
fn keygen_device_key() {
    let key = keygen::generate_device_key(keygen::ES256).unwrap();
    let cbor = keygen::serialize_key(&key, true).unwrap();
    assert!(!cbor.is_empty());
}

#[test]
fn keygen_pem_roundtrip() {
    let key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let pem_str = keygen::serialize_key_pem(&key, true).unwrap();
    assert!(pem_str.contains("BEGIN PRIVATE KEY"));
    let restored = CoseKey::from_pem(&pem_str).unwrap();
    assert!(!restored.public_key_bytes().is_empty());
}

#[test]
fn encrypt_build_validate_decrypt() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"Hello, SUIT firmware update!";

    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image(firmware, &signing_key, &recipients, false);

    // Validate
    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();
    assert_eq!(manifest.sequence_number(), 42);
    assert_eq!(manifest.component_count(), 1);

    // Decrypt
    let device_key_coset = coset::CoseKey::from_slice(&device_kek.to_cose_key_bytes()).unwrap();
    let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key_coset, &crypto).unwrap();

    let mut plaintext = vec![0u8; ciphertext.len() + 256];
    let mut total = 0;
    total += decryptor.update(&ciphertext, &mut plaintext[total..]).unwrap();
    total += decryptor.finalize(&mut plaintext[total..]).unwrap();

    assert_eq!(&plaintext[..total], firmware);
}

#[test]
fn streaming_decrypt_small_chunks() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = vec![0xAB; 256];

    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image(&firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let validator = Validator::new(&trust_anchor, None);
    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let device_key_coset = coset::CoseKey::from_slice(&device_kek.to_cose_key_bytes()).unwrap();
    let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key_coset, &crypto).unwrap();

    // Feed in 7-byte chunks (note: streaming impl accumulates, outputs all on finalize)
    let mut plaintext = Vec::new();
    let mut buf = vec![0u8; ciphertext.len() + 256];
    for chunk in ciphertext.chunks(7) {
        let n = decryptor.update(chunk, &mut buf).unwrap();
        plaintext.extend_from_slice(&buf[..n]);
    }
    let n = decryptor.finalize(&mut buf).unwrap();
    plaintext.extend_from_slice(&buf[..n]);

    assert_eq!(plaintext, firmware);
}

#[test]
fn realistic_streaming_1mb() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    // 1MB firmware with pattern
    let firmware: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();

    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image(&firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let validator = Validator::new(&trust_anchor, None);
    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let device_key_coset = coset::CoseKey::from_slice(&device_kek.to_cose_key_bytes()).unwrap();
    let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key_coset, &crypto).unwrap();

    // Stream in 4KB chunks
    let mut buf = vec![0u8; firmware.len() + 256];
    let mut total_pt = 0usize;

    for chunk in ciphertext.chunks(4096) {
        let n = decryptor.update(chunk, &mut buf[total_pt..]).unwrap();
        total_pt += n;
    }
    let n = decryptor.finalize(&mut buf[total_pt..]).unwrap();
    total_pt += n;

    assert_eq!(total_pt, firmware.len());
    let computed = crypto.sha256(&buf[..total_pt]);
    let expected = crypto.sha256(&firmware);
    assert_eq!(computed, expected);
}

#[test]
fn compress_encrypt_decrypt_decompress() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();

    // Compress
    let compressed = encryptor::compress_firmware(&firmware, 3).unwrap();
    assert!(compressed.len() < firmware.len());

    // Encrypt the compressed data
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let encrypted = encryptor::encrypt_firmware(&compressed, &recipients).unwrap();
    let digest = encryptor::sha256(&firmware);

    let envelope_bytes = ImageManifestBuilder::new()
        .component_id(vec!["ecu-a".into(), "firmware".into()])
        .sequence_number(42)
        .vendor_id(test_vendor())
        .class_id(test_class())
        .payload_digest(&digest, firmware.len() as u64)
        .payload_uri("https://fw.example.com/ecu-a.enc".into())
        .encryption_info(&encrypted.encryption_info)
        .build(&signing_key)
        .unwrap();

    // Validate
    let trust_anchor = signing_key.public_key_bytes();
    let validator = Validator::new(&trust_anchor, None);
    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    // Decrypt
    let device_key_coset = coset::CoseKey::from_slice(&device_kek.to_cose_key_bytes()).unwrap();
    let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key_coset, &crypto).unwrap();

    let mut decrypted = Vec::new();
    let mut buf = vec![0u8; 4096 + 256];
    for chunk in encrypted.ciphertext.chunks(4096) {
        let n = decryptor.update(chunk, &mut buf).unwrap();
        decrypted.extend_from_slice(&buf[..n]);
    }
    let n = decryptor.finalize(&mut buf).unwrap();
    decrypted.extend_from_slice(&buf[..n]);

    // Decompress
    let mut decompressor = StreamingDecompressor::new().unwrap();
    let mut _out = [0u8; 0];
    decompressor.update(&decrypted, &mut _out).unwrap();
    let result = decompressor.finalize_to_vec().unwrap();

    assert_eq!(result, firmware);
}

#[test]
fn ecdh_encrypt_decrypt() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let sender_key = keygen::generate_device_key(keygen::ES256).unwrap();
    let device_key = keygen::generate_device_key(keygen::ES256).unwrap();

    let firmware = b"ECDH-encrypted firmware payload";

    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_key.public_key_bytes()).unwrap(),
        kid: b"device-ecdh".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image_ecdh(
        firmware, &signing_key, &sender_key, &recipients,
    );

    // Validate
    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_key.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    // Decrypt with device private key
    let device_key_coset = coset::CoseKey::from_slice(&device_key.to_cose_key_bytes()).unwrap();
    let mut decryptor = StreamingDecryptor::new(&manifest, 0, &device_key_coset, &crypto).unwrap();

    let mut plaintext = vec![0u8; ciphertext.len() + 256];
    let mut total = 0;
    total += decryptor.update(&ciphertext, &mut plaintext[total..]).unwrap();
    total += decryptor.finalize(&mut plaintext[total..]).unwrap();

    assert_eq!(&plaintext[..total], firmware);
}

#[test]
fn wrong_signing_key_rejected() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let wrong_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"test payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, _) = build_test_image(firmware, &signing_key, &recipients, false);

    // Validate with wrong trust anchor
    let wrong_anchor = wrong_key.public_key_bytes();
    let validator = Validator::new(&wrong_anchor, None);
    let result = validator.validate_envelope(&envelope_bytes, &crypto, 0);
    assert_eq!(result.unwrap_err(), Sum2Error::AuthFailed);
}

#[test]
fn rollback_rejected() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"test payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, _) = build_test_image(firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    // Sequence 42 in manifest, set min to 42 → should reject (must be strictly >)
    validator.set_min_sequence(42);

    let result = validator.validate_envelope(&envelope_bytes, &crypto, 0);
    assert_eq!(result.unwrap_err(), Sum2Error::RollbackRejected);
}

#[test]
fn policy_load_save_roundtrip() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"test payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, _) = build_test_image(firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let validator = Validator::new(&trust_anchor, None);
    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    // Save policy
    let storage = FakeStorageOps::new();
    policy::policy_save(&manifest, &storage).unwrap();

    // Load policy into a new validator
    let mut validator2 = Validator::new(&trust_anchor, None);
    policy::policy_load(&mut validator2, &storage).unwrap();

    // Now the same manifest should be rejected (rollback)
    let result = validator2.validate_envelope(&envelope_bytes, &crypto, 0);
    assert_eq!(result.unwrap_err(), Sum2Error::RollbackRejected);
}

#[test]
fn policy_load_empty_storage() {
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    let storage = FakeStorageOps::new();

    // Should succeed with no stored values
    policy::policy_load(&mut validator, &storage).unwrap();
}

#[test]
fn process_image_a128kw() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"orchestrated firmware payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image(firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let ops = FakePlatformOps::new();
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    orchestrator::process_image(&validator, &manifest, &ops, &crypto).unwrap();

    let written = ops.get_written(b"ecu-a/firmware");
    assert_eq!(written, firmware);
}

#[test]
fn process_image_ecdh() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let sender_key = keygen::generate_device_key(keygen::ES256).unwrap();
    let device_key = keygen::generate_device_key(keygen::ES256).unwrap();

    let firmware = b"ECDH orchestrated firmware";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_key.public_key_bytes()).unwrap(),
        kid: b"device-ecdh".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image_ecdh(
        firmware, &signing_key, &sender_key, &recipients,
    );

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_key.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let ops = FakePlatformOps::new();
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    orchestrator::process_image(&validator, &manifest, &ops, &crypto).unwrap();

    let written = ops.get_written(b"ecu-a/firmware");
    assert_eq!(written, firmware);
}

use coset::CborSerializable;

// ============================================================
// Campaign E2E Tests
// ============================================================

/// Helper to build an L2 image manifest with a specific component ID and URI.
fn build_l2_image(
    firmware: &[u8],
    comp_id: Vec<String>,
    uri: &str,
    seq: u64,
    signing_key: &CoseKey,
    device_kek: &CoseKey,
) -> (Vec<u8>, Vec<u8>) {
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let encrypted = encryptor::encrypt_firmware(firmware, &recipients).unwrap();
    let digest = encryptor::sha256(firmware);

    let envelope = ImageManifestBuilder::new()
        .component_id(comp_id)
        .sequence_number(seq)
        .vendor_id(test_vendor())
        .class_id(test_class())
        .payload_digest(&digest, firmware.len() as u64)
        .payload_uri(uri.into())
        .encryption_info(&encrypted.encryption_info)
        .build(signing_key)
        .unwrap();

    (envelope, encrypted.ciphertext)
}

#[test]
fn process_campaign_two_images() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let fw_a = b"firmware for ECU-A v2.0";
    let fw_b = b"firmware for ECU-B v3.1";

    let (l2_a, ct_a) = build_l2_image(
        fw_a, vec!["ecu-a".into(), "firmware".into()],
        "https://fw.example.com/ecu-a.enc", 100, &signing_key, &device_kek,
    );
    let (l2_b, ct_b) = build_l2_image(
        fw_b, vec!["ecu-b".into(), "firmware".into()],
        "https://fw.example.com/ecu-b.enc", 100, &signing_key, &device_kek,
    );

    // Build campaign
    let campaign = CampaignBuilder::new()
        .sequence_number(200)
        .vendor_id(test_vendor())
        .class_id(test_class())
        .add_image("https://manifests.example.com/l2-a.suit".into(), &l2_a)
        .add_image("https://manifests.example.com/l2-b.suit".into(), &l2_b)
        .build(&signing_key)
        .unwrap();

    // Set up validator and platform
    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&campaign, &crypto, 0).unwrap();
    assert!(manifest.is_campaign());
    assert_eq!(manifest.dependency_count(), 2);

    let ops = FakePlatformOps::new();
    ops.add_fetch("https://manifests.example.com/l2-a.suit", l2_a);
    ops.add_fetch("https://manifests.example.com/l2-b.suit", l2_b);
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ct_a);
    ops.add_fetch("https://fw.example.com/ecu-b.enc", ct_b);

    orchestrator::process_campaign(&validator, &manifest, &ops, &crypto).unwrap();

    assert_eq!(ops.get_written(b"ecu-a/firmware"), fw_a);
    assert_eq!(ops.get_written(b"ecu-b/firmware"), fw_b);
}

#[test]
fn process_campaign_integrated_payloads() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let fw = b"integrated firmware payload";

    let (l2_env, ciphertext) = build_l2_image(
        fw, vec!["ecu-a".into(), "firmware".into()],
        "https://fw.example.com/ecu-a.enc", 100, &signing_key, &device_kek,
    );

    // Build campaign with integrated L2 manifest
    let campaign = CampaignBuilder::new()
        .sequence_number(200)
        .vendor_id(test_vendor())
        .class_id(test_class())
        .add_integrated_image("l2-manifest".into(), &l2_env)
        .build(&signing_key)
        .unwrap();

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&campaign, &crypto, 0).unwrap();
    assert!(manifest.is_campaign());

    let ops = FakePlatformOps::new();
    // Only need the firmware payload fetch, not the L2 manifest (it's integrated)
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    orchestrator::process_campaign(&validator, &manifest, &ops, &crypto).unwrap();

    assert_eq!(ops.get_written(b"ecu-a/firmware"), fw);
}

// ============================================================
// Orchestrator + Compression Tests
// ============================================================

#[test]
fn process_image_with_compression() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    // Use repetitive data that compresses well
    let firmware: Vec<u8> = (0..16384u32).map(|i| (i % 7) as u8).collect();

    let (envelope_bytes, ciphertext) = build_test_image(
        &firmware, &signing_key,
        &[Recipient {
            public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
            kid: b"device-1".to_vec(),
        }],
        true, // compress
    );

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let ops = FakePlatformOps::new();
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    orchestrator::process_image(&validator, &manifest, &ops, &crypto).unwrap();

    let written = ops.get_written(b"ecu-a/firmware");
    assert_eq!(written, firmware);
}

// ============================================================
// Error Case Tests
// ============================================================

#[test]
fn process_image_fetch_fails() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"test payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, _ciphertext) = build_test_image(firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    // Don't add fetch data — fetch should fail
    let ops = FakePlatformOps::new();

    let result = orchestrator::process_image(&validator, &manifest, &ops, &crypto);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Sum2Error::CallbackFailed);
}

#[test]
fn process_image_tampered_payload() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"original firmware content";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, mut ciphertext) = build_test_image(firmware, &signing_key, &recipients, false);

    // Tamper with the ciphertext (flip a byte early in the payload, before GCM tag)
    if ciphertext.len() > 5 {
        ciphertext[5] ^= 0xFF;
    }

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let ops = FakePlatformOps::new();
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    // Should fail due to GCM tag verification or digest mismatch
    let result = orchestrator::process_image(&validator, &manifest, &ops, &crypto);
    assert!(result.is_err());
}

#[test]
fn process_image_no_device_key() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"test payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image(firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    // No device key added to validator
    let validator = Validator::new(&trust_anchor, None);

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();

    let ops = FakePlatformOps::new();
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    let result = orchestrator::process_image(&validator, &manifest, &ops, &crypto);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), Sum2Error::DecryptFailed);
}

#[test]
fn campaign_empty_deps_rejected() {
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();

    let result = CampaignBuilder::new()
        .sequence_number(1)
        .build(&signing_key);

    assert!(result.is_err());
}

#[test]
fn process_campaign_fetch_l2_fails() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::ES256).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let fw = b"firmware data";
    let (l2_env, _ct) = build_l2_image(
        fw, vec!["ecu-a".into(), "firmware".into()],
        "https://fw.example.com/ecu-a.enc", 100, &signing_key, &device_kek,
    );

    let campaign = CampaignBuilder::new()
        .sequence_number(200)
        .vendor_id(test_vendor())
        .add_image("https://manifests.example.com/l2.suit".into(), &l2_env)
        .build(&signing_key)
        .unwrap();

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&campaign, &crypto, 0).unwrap();

    // Don't add the L2 manifest fetch data
    let ops = FakePlatformOps::new();

    let result = orchestrator::process_campaign(&validator, &manifest, &ops, &crypto);
    assert!(result.is_err());
}

// ============================================================
// EdDSA E2E Test
// ============================================================

#[test]
fn eddsa_sign_validate_roundtrip() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::EDDSA).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"EdDSA-signed firmware payload";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, ciphertext) = build_test_image(firmware, &signing_key, &recipients, false);

    let trust_anchor = signing_key.public_key_bytes();
    let mut validator = Validator::new(&trust_anchor, None);
    validator.add_device_key(&device_kek.to_cose_key_bytes()).unwrap();

    let manifest = validator.validate_envelope(&envelope_bytes, &crypto, 0).unwrap();
    assert_eq!(manifest.sequence_number(), 42);

    // Decrypt and verify
    let ops = FakePlatformOps::new();
    ops.add_fetch("https://fw.example.com/ecu-a.enc", ciphertext);

    orchestrator::process_image(&validator, &manifest, &ops, &crypto).unwrap();
    assert_eq!(ops.get_written(b"ecu-a/firmware"), firmware);
}

#[test]
fn eddsa_wrong_key_rejected() {
    let crypto = RustCryptoBackend::new();
    let signing_key = keygen::generate_signing_key(keygen::EDDSA).unwrap();
    let wrong_key = keygen::generate_signing_key(keygen::EDDSA).unwrap();
    let device_kek = generate_a128kw_key(b"device-1");

    let firmware = b"EdDSA test";
    let recipients = [Recipient {
        public_key: CoseKey::from_cose_key_bytes(&device_kek.to_cose_key_bytes()).unwrap(),
        kid: b"device-1".to_vec(),
    }];

    let (envelope_bytes, _) = build_test_image(firmware, &signing_key, &recipients, false);

    let wrong_anchor = wrong_key.public_key_bytes();
    let validator = Validator::new(&wrong_anchor, None);
    let result = validator.validate_envelope(&envelope_bytes, &crypto, 0);
    assert_eq!(result.unwrap_err(), Sum2Error::AuthFailed);
}
