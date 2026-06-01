//! Firmware encryption and compression.

use ciborium::value::{Integer, Value};

use crate::cose_key::CoseKey;
use crate::error::OffboardError;
use crate::recipient::Recipient;
use sumo_crypto::cose_key as ck;
use sumo_crypto::CryptoBackend;

/// Encrypted payload: ciphertext + COSE_Encrypt info + plaintext CEK.
///
/// The CEK (Content Encryption Key) is included so callers can persist it
/// and later re-wrap it for additional device keys without re-encrypting
/// the payload. Treat the CEK as highly sensitive.
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub encryption_info: Vec<u8>,
    pub cek: [u8; 16],
}

/// Encrypt firmware with A128KW key wrapping.
///
/// Each recipient must have a symmetric KEK as their key material.
/// Returns ciphertext (AES-GCM with appended tag) and COSE_Encrypt CBOR.
pub fn encrypt_firmware(
    plaintext: &[u8],
    recipients: &[Recipient],
) -> Result<EncryptedPayload, OffboardError> {
    let crypto = sumo_crypto::RustCryptoBackend::new();

    // Generate random CEK and IV
    let mut cek = [0u8; 16];
    let mut iv = [0u8; 12];
    crypto
        .random_bytes(&mut cek)
        .map_err(|e| OffboardError::Crypto(e))?;
    crypto
        .random_bytes(&mut iv)
        .map_err(|e| OffboardError::Crypto(e))?;

    // Encrypt plaintext with AES-128-GCM
    let ciphertext = crypto
        .aes_gcm_encrypt(&cek, &iv, &[], plaintext)
        .map_err(|e| OffboardError::Crypto(e))?;

    // Wrap CEK for each recipient using A128KW
    let mut rcpt_values = Vec::new();
    for r in recipients {
        let kek = extract_symmetric_key(r.public_key.inner())?;
        let wrapped = crypto
            .aes_kw_wrap(&kek, &cek)
            .map_err(|e| OffboardError::Crypto(e))?;

        // COSE_recipient = [protected, unprotected, ciphertext]
        let rcpt = Value::Array(vec![
            Value::Bytes(Vec::new()), // empty protected
            Value::Map(vec![
                (int_val(1), int_val(ck::COSE_ALG_A128KW)), // algorithm
                (int_val(4), Value::Bytes(r.kid.clone())),  // kid
            ]),
            Value::Bytes(wrapped),
        ]);
        rcpt_values.push(rcpt);
    }

    let encryption_info = build_cose_encrypt(&iv, rcpt_values)?;
    Ok(EncryptedPayload {
        ciphertext,
        encryption_info,
        cek,
    })
}

/// Encrypt firmware with ECDH-ES+A128KW key agreement.
///
/// Each recipient has a P-256 public key. A fresh ephemeral key is used for each recipient.
pub fn encrypt_firmware_ecdh(
    plaintext: &[u8],
    sender_key: &CoseKey,
    recipients: &[Recipient],
) -> Result<EncryptedPayload, OffboardError> {
    let crypto = sumo_crypto::RustCryptoBackend::new();

    // Generate random CEK and IV
    let mut cek = [0u8; 16];
    let mut iv = [0u8; 12];
    crypto
        .random_bytes(&mut cek)
        .map_err(|e| OffboardError::Crypto(e))?;
    crypto
        .random_bytes(&mut iv)
        .map_err(|e| OffboardError::Crypto(e))?;

    // Encrypt plaintext with AES-128-GCM
    let ciphertext = crypto
        .aes_gcm_encrypt(&cek, &iv, &[], plaintext)
        .map_err(|e| OffboardError::Crypto(e))?;

    // Extract sender private key
    let sender_ec2 = ck::extract_ec2(sender_key.inner()).map_err(|e| OffboardError::Crypto(e))?;
    let sender_d = sender_ec2
        .d
        .ok_or_else(|| OffboardError::Other("sender key missing private material".into()))?;

    // Build sender public key as COSE_Key for recipient unprotected header
    let sender_pub = build_ec2_pub_cose_key(&sender_ec2.x, &sender_ec2.y);

    // Protected header for ECDH-ES+A128KW: {1: -29}
    let protected = encode_protected_alg(ck::COSE_ALG_ECDH_ES_A128KW)?;

    // Wrap CEK for each recipient using ECDH-ES+A128KW
    let mut rcpt_values = Vec::new();
    for r in recipients {
        let rcpt_ec2 =
            ck::extract_ec2(r.public_key.inner()).map_err(|e| OffboardError::Crypto(e))?;
        let mut rcpt_pub = [0u8; 65];
        rcpt_pub[0] = 0x04;
        rcpt_pub[1..33].copy_from_slice(&rcpt_ec2.x);
        rcpt_pub[33..65].copy_from_slice(&rcpt_ec2.y);

        let wrapped = sumo_crypto::ecdh_es::ecdh_es_a128kw_wrap(
            &crypto, &sender_d, &rcpt_pub, &cek, &protected,
        )
        .map_err(|e| OffboardError::Crypto(e))?;

        // COSE_recipient = [protected, unprotected, ciphertext]
        let rcpt = Value::Array(vec![
            Value::Bytes(protected.clone()),
            Value::Map(vec![
                (int_val(4), Value::Bytes(r.kid.clone())), // kid
                (int_val(-1), sender_pub.clone()),         // ephemeral key
            ]),
            Value::Bytes(wrapped),
        ]);
        rcpt_values.push(rcpt);
    }

    let encryption_info = build_cose_encrypt(&iv, rcpt_values)?;
    Ok(EncryptedPayload {
        ciphertext,
        encryption_info,
        cek,
    })
}

/// Extract the IV from an existing COSE_Encrypt CBOR structure (enc-info file).
///
/// Used for rewrap: read the original enc-info to get the IV, then
/// build a new COSE_Encrypt with the same IV but different recipients.
pub fn extract_iv_from_enc_info(enc_info: &[u8]) -> Result<[u8; 12], OffboardError> {
    let value: Value = ciborium::de::from_reader(enc_info)
        .map_err(|_| OffboardError::Other("invalid COSE_Encrypt CBOR".into()))?;

    let arr = match &value {
        Value::Array(a) => a,
        _ => return Err(OffboardError::Other("COSE_Encrypt not an array".into())),
    };

    if arr.len() < 2 {
        return Err(OffboardError::Other("COSE_Encrypt too short".into()));
    }

    // arr[1] = unprotected header map, IV is label 5
    let iv_bytes = match &arr[1] {
        Value::Map(entries) => entries
            .iter()
            .find_map(|(k, v)| {
                if let (Value::Integer(i), Value::Bytes(b)) = (k, v) {
                    if i128::from(*i) == 5 {
                        Some(b.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| OffboardError::Other("IV not found in COSE_Encrypt".into()))?,
        _ => return Err(OffboardError::Other("unprotected header not a map".into())),
    };

    if iv_bytes.len() != 12 {
        return Err(OffboardError::Other(format!(
            "IV is {} bytes, expected 12",
            iv_bytes.len()
        )));
    }
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    Ok(iv)
}

/// Re-wrap an existing CEK for a new ECDH-ES+A128KW recipient.
///
/// Produces a new COSE_Encrypt structure that reuses the same IV
/// (so the existing ciphertext remains valid) but wraps the CEK for a
/// different device's public key using a fresh ephemeral sender key.
///
/// Use case: firmware was encrypted once with a random CEK. For each new
/// device, re-wrap the CEK for that device's key — no re-encryption needed.
pub fn rewrap_cek_ecdh(
    cek: &[u8; 16],
    iv: &[u8; 12],
    recipient: &Recipient,
) -> Result<Vec<u8>, OffboardError> {
    let crypto = sumo_crypto::RustCryptoBackend::new();

    // Generate fresh ephemeral sender key for this recipient
    let sender_key = crate::keygen::generate_device_key(crate::keygen::ES256)?;
    let sender_ec2 = ck::extract_ec2(sender_key.inner()).map_err(|e| OffboardError::Crypto(e))?;
    let sender_d = sender_ec2
        .d
        .ok_or_else(|| OffboardError::Other("ephemeral key missing private material".into()))?;
    let sender_pub = build_ec2_pub_cose_key(&sender_ec2.x, &sender_ec2.y);

    // Protected header for ECDH-ES+A128KW: {1: -29}
    let protected = encode_protected_alg(ck::COSE_ALG_ECDH_ES_A128KW)?;

    // Extract recipient public key
    let rcpt_ec2 =
        ck::extract_ec2(recipient.public_key.inner()).map_err(|e| OffboardError::Crypto(e))?;
    let mut rcpt_pub = [0u8; 65];
    rcpt_pub[0] = 0x04;
    rcpt_pub[1..33].copy_from_slice(&rcpt_ec2.x);
    rcpt_pub[33..65].copy_from_slice(&rcpt_ec2.y);

    // Wrap CEK for the recipient
    let wrapped =
        sumo_crypto::ecdh_es::ecdh_es_a128kw_wrap(&crypto, &sender_d, &rcpt_pub, cek, &protected)
            .map_err(|e| OffboardError::Crypto(e))?;

    // Build single COSE_recipient
    let rcpt_value = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(vec![
            (int_val(4), Value::Bytes(recipient.kid.clone())),
            (int_val(-1), sender_pub),
        ]),
        Value::Bytes(wrapped),
    ]);

    build_cose_encrypt(iv, vec![rcpt_value])
}

/// Compress firmware with zstd.
///
/// `window_log`, if set, overrides zstd's default window selection.
/// Constrained devices need this — the on-device decoder allocates a
/// per-frame buffer sized after the frame header's `windowLog`, and
/// zstd's stock level-based default (e.g. 19 = 512 KB at level 3)
/// blows the heap on Cortex-M class targets. Pick the smallest value
/// that still covers your firmware blobs (e.g. 10 = 1 KB window;
/// 17 = 128 KB).
pub fn compress_firmware(
    plaintext: &[u8],
    level: i32,
    window_log: Option<u32>,
) -> Result<Vec<u8>, OffboardError> {
    use std::io::Write;
    let mut encoder = zstd::Encoder::new(Vec::new(), level).map_err(OffboardError::Io)?;
    if let Some(wl) = window_log {
        encoder
            .set_parameter(zstd::stream::raw::CParameter::WindowLog(wl))
            .map_err(OffboardError::Io)?;
    }
    encoder.write_all(plaintext).map_err(OffboardError::Io)?;
    encoder.finish().map_err(OffboardError::Io)
}

/// Compute SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sumo_crypto::RustCryptoBackend::new().sha256(data)
}

// --- Helpers ---

fn build_cose_encrypt(iv: &[u8; 12], recipients: Vec<Value>) -> Result<Vec<u8>, OffboardError> {
    // protected header: {1: 1} = AES-128-GCM
    let protected = encode_protected_alg(1)?; // A128GCM = 1

    let cose_encrypt = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(vec![(int_val(5), Value::Bytes(iv.to_vec()))]), // unprotected: {5: IV}
        Value::Null,                                               // detached ciphertext
        Value::Array(recipients),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cose_encrypt, &mut buf)
        .map_err(|_| OffboardError::Other("CBOR encode failed".into()))?;
    Ok(buf)
}

fn encode_protected_alg(alg: i64) -> Result<Vec<u8>, OffboardError> {
    let map = Value::Map(vec![(int_val(1), int_val(alg))]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&map, &mut buf)
        .map_err(|_| OffboardError::Other("CBOR encode failed".into()))?;
    Ok(buf)
}

fn build_ec2_pub_cose_key(x: &[u8], y: &[u8]) -> Value {
    Value::Map(vec![
        (int_val(1), int_val(2)),                // kty: EC2
        (int_val(-1), int_val(1)),               // crv: P-256
        (int_val(-2), Value::Bytes(x.to_vec())), // x
        (int_val(-3), Value::Bytes(y.to_vec())), // y
    ])
}

fn int_val(v: i64) -> Value {
    Value::Integer(Integer::from(v))
}

fn extract_symmetric_key(key: &coset::CoseKey) -> Result<Vec<u8>, OffboardError> {
    for (label, value) in &key.params {
        if let coset::Label::Int(-1) = label {
            if let ciborium::value::Value::Bytes(b) = value {
                return Ok(b.clone());
            }
        }
    }
    Err(OffboardError::Other(
        "symmetric key material not found in CoseKey".into(),
    ))
}
