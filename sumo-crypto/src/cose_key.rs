//! COSE_Key parsing and construction helpers.
//!
//! Supports EC2 (P-256) and OKP (Ed25519/X25519) key types.

use crate::error::CryptoError;
use coset::CborSerializable;
use coset::iana::EnumI64;

// COSE_Key map labels
pub const COSE_KEY_KTY: i64 = 1;
pub const COSE_KEY_KID: i64 = 2;
pub const COSE_KEY_ALG: i64 = 3;
pub const COSE_KEY_CRV: i64 = -1;
pub const COSE_KEY_X: i64 = -2;
pub const COSE_KEY_Y: i64 = -3;
pub const COSE_KEY_D: i64 = -4;

// Key types
pub const COSE_KTY_OKP: i64 = 1;
pub const COSE_KTY_EC2: i64 = 2;
pub const COSE_KTY_SYMMETRIC: i64 = 4;

// Curves
pub const COSE_CRV_P256: i64 = 1;
pub const COSE_CRV_ED25519: i64 = 6;
pub const COSE_CRV_X25519: i64 = 4;

// Algorithms
pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;
pub const COSE_ALG_A128KW: i64 = -3;
pub const COSE_ALG_ECDH_ES_A128KW: i64 = -29;
pub const COSE_ALG_A128GCM: i64 = 1;

/// Parsed EC2 P-256 key components.
pub struct Ec2Key {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub d: Option<[u8; 32]>,
}

/// Parsed OKP (Ed25519/X25519) key components.
pub struct OkpKey {
    pub crv: i64,
    pub x: Vec<u8>, // public key bytes
    pub d: Option<Vec<u8>>, // private key bytes
}

/// Parse a COSE_Key from CBOR bytes into its components.
pub fn parse_cose_key_cbor(cbor: &[u8]) -> Result<coset::CoseKey, CryptoError> {
    coset::CoseKey::from_slice(cbor).map_err(|_| CryptoError::InvalidKey)
}

/// Extract EC2 P-256 key components from a CoseKey.
pub fn extract_ec2(key: &coset::CoseKey) -> Result<Ec2Key, CryptoError> {
    use coset::iana;

    // Check key type
    match key.kty {
        coset::KeyType::Assigned(iana::KeyType::EC2) => {}
        _ => return Err(CryptoError::InvalidKey),
    }

    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    let mut d = None;

    for (label, value) in &key.params {
        match label {
            coset::Label::Int(COSE_KEY_X) => {
                if let ciborium::value::Value::Bytes(b) = value {
                    if b.len() == 32 {
                        x.copy_from_slice(b);
                    }
                }
            }
            coset::Label::Int(COSE_KEY_Y) => {
                if let ciborium::value::Value::Bytes(b) = value {
                    if b.len() == 32 {
                        y.copy_from_slice(b);
                    }
                }
            }
            coset::Label::Int(COSE_KEY_D) => {
                if let ciborium::value::Value::Bytes(b) = value {
                    if b.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(b);
                        d = Some(arr);
                    }
                }
            }
            _ => {}
        }
    }

    // Verify we got x and y
    if x == [0u8; 32] {
        return Err(CryptoError::InvalidKey);
    }

    Ok(Ec2Key { x, y, d })
}

/// Extract OKP key components from a CoseKey.
pub fn extract_okp(key: &coset::CoseKey) -> Result<OkpKey, CryptoError> {
    use coset::iana;

    match key.kty {
        coset::KeyType::Assigned(iana::KeyType::OKP) => {}
        _ => return Err(CryptoError::InvalidKey),
    }

    let mut crv: i64 = 0;
    let mut x_bytes: Option<Vec<u8>> = None;
    let mut d_bytes: Option<Vec<u8>> = None;

    for (label, value) in &key.params {
        match label {
            coset::Label::Int(COSE_KEY_CRV) => {
                if let ciborium::value::Value::Integer(i) = value {
                    crv = i128::from(*i) as i64;
                }
            }
            coset::Label::Int(COSE_KEY_X) => {
                if let ciborium::value::Value::Bytes(b) = value {
                    x_bytes = Some(b.clone());
                }
            }
            coset::Label::Int(COSE_KEY_D) => {
                if let ciborium::value::Value::Bytes(b) = value {
                    d_bytes = Some(b.clone());
                }
            }
            _ => {}
        }
    }

    let x = x_bytes.ok_or(CryptoError::InvalidKey)?;
    Ok(OkpKey { crv, x, d: d_bytes })
}

/// Get the algorithm from a CoseKey.
pub fn key_algorithm(key: &coset::CoseKey) -> Option<i64> {
    match &key.alg {
        Some(coset::Algorithm::Assigned(a)) => Some(a.to_i64()),
        Some(coset::Algorithm::PrivateUse(v)) => Some(*v),
        _ => None,
    }
}
