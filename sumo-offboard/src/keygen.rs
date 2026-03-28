//! Key generation for signing and device keys.

use crate::cose_key::{CoseKey, p256_secret_to_cose, ed25519_signing_to_cose};
use crate::error::OffboardError;
use coset::Label;

/// COSE algorithm identifiers.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;

/// Generate a signing keypair (ES256 or EdDSA).
pub fn generate_signing_key(algorithm: i64) -> Result<CoseKey, OffboardError> {
    match algorithm {
        ES256 => {
            let sk = p256::SecretKey::random(&mut rand::thread_rng());
            Ok(CoseKey::from_coset(p256_secret_to_cose(&sk)))
        }
        EDDSA => {
            let mut rng = rand::thread_rng();
            let sk = ed25519_dalek::SigningKey::generate(&mut rng);
            Ok(CoseKey::from_coset(ed25519_signing_to_cose(&sk)))
        }
        _ => Err(OffboardError::Other(format!("unsupported algorithm: {algorithm}"))),
    }
}

/// Generate a device key agreement keypair (P-256 ECDH).
pub fn generate_device_key(algorithm: i64) -> Result<CoseKey, OffboardError> {
    match algorithm {
        ES256 => {
            // P-256 ECDH key (same structure as ES256 but used for key agreement)
            let sk = p256::SecretKey::random(&mut rand::thread_rng());
            let mut cose = p256_secret_to_cose(&sk);
            // Clear algorithm — device keys are for ECDH, not signing
            cose.alg = None;
            Ok(CoseKey::from_coset(cose))
        }
        _ => Err(OffboardError::Other(format!("unsupported device key algorithm: {algorithm}"))),
    }
}

/// Serialize a key as CBOR COSE_Key bytes.
pub fn serialize_key(key: &CoseKey, include_private: bool) -> Result<Vec<u8>, OffboardError> {
    if include_private {
        Ok(key.to_cose_key_bytes())
    } else {
        Ok(key.public_key_bytes())
    }
}

/// Serialize a key as PEM string.
pub fn serialize_key_pem(key: &CoseKey, include_private: bool) -> Result<String, OffboardError> {
    use p256::pkcs8::EncodePrivateKey;
    let inner = key.inner();

    // Check key type
    match inner.kty {
        coset::KeyType::Assigned(coset::iana::KeyType::EC2) => {
            // P-256 key — extract d to reconstruct SecretKey
            if include_private {
                let d = extract_param_bytes(inner, -4)?;
                let sk = p256::SecretKey::from_bytes(d.as_slice().into())
                    .map_err(|e| OffboardError::Other(format!("invalid P-256 key: {e}")))?;
                let pem_str = sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| OffboardError::Other(format!("PEM encode failed: {e}")))?;
                Ok(pem_str.to_string())
            } else {
                // Export public key PEM
                let x = extract_param_bytes(inner, -2)?;
                let y = extract_param_bytes(inner, -3)?;
                let mut uncompressed = Vec::with_capacity(65);
                uncompressed.push(0x04);
                uncompressed.extend_from_slice(&x);
                uncompressed.extend_from_slice(&y);
                let pk = p256::PublicKey::from_sec1_bytes(&uncompressed)
                    .map_err(|e| OffboardError::Other(format!("invalid P-256 public key: {e}")))?;
                use p256::pkcs8::EncodePublicKey;
                let pem_str = pk.to_public_key_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| OffboardError::Other(format!("PEM encode failed: {e}")))?;
                Ok(pem_str)
            }
        }
        coset::KeyType::Assigned(coset::iana::KeyType::OKP) => {
            use ed25519_dalek::pkcs8::EncodePrivateKey as EdEncodePrivateKey;
            if include_private {
                let d = extract_param_bytes(inner, -4)?;
                let sk = ed25519_dalek::SigningKey::from_bytes(
                    d.as_slice().try_into()
                        .map_err(|_| OffboardError::Other("invalid Ed25519 key length".into()))?
                );
                let pem_str = sk.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(|e| OffboardError::Other(format!("PEM encode failed: {e}")))?;
                Ok(pem_str.to_string())
            } else {
                Err(OffboardError::Other("Ed25519 public-only PEM not supported".into()))
            }
        }
        _ => Err(OffboardError::Other("unsupported key type for PEM export".into())),
    }
}

fn extract_param_bytes(key: &coset::CoseKey, label: i64) -> Result<Vec<u8>, OffboardError> {
    for (l, v) in &key.params {
        if *l == Label::Int(label) {
            if let ciborium::value::Value::Bytes(b) = v {
                return Ok(b.clone());
            }
        }
    }
    Err(OffboardError::Other(format!("missing key parameter {label}")))
}
