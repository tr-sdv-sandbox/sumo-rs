//! COSE key management with import/export.

use crate::error::OffboardError;
use coset::{iana, CborSerializable, Label};

/// A COSE key with optional private material.
pub struct CoseKey {
    inner: coset::CoseKey,
}

impl CoseKey {
    /// Wrap an existing coset::CoseKey.
    pub(crate) fn from_coset(inner: coset::CoseKey) -> Self {
        Self { inner }
    }

    /// Import from CBOR-encoded COSE_Key bytes.
    pub fn from_cose_key_bytes(cbor: &[u8]) -> Result<Self, OffboardError> {
        let key = coset::CoseKey::from_slice(cbor)
            .map_err(|e| OffboardError::Other(format!("invalid COSE_Key CBOR: {e}")))?;
        Ok(Self { inner: key })
    }

    /// Import from PEM-encoded key string (PKCS8 or SEC1 P-256 key).
    pub fn from_pem(pem_str: &str) -> Result<Self, OffboardError> {
        use p256::pkcs8::DecodePrivateKey;

        // Try P-256 private key
        if let Ok(sk) = p256::SecretKey::from_pkcs8_pem(pem_str) {
            return Ok(Self::from_coset(p256_secret_to_cose(&sk)));
        }

        // Try Ed25519 private key
        #[allow(unused_imports)]
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem_str) {
            return Ok(Self::from_coset(ed25519_signing_to_cose(&sk)));
        }

        Err(OffboardError::Other("unsupported PEM key format".into()))
    }

    /// Import from DER-encoded key bytes (PKCS8 P-256 or Ed25519).
    pub fn from_der(der: &[u8]) -> Result<Self, OffboardError> {
        use p256::pkcs8::DecodePrivateKey;

        if let Ok(sk) = p256::SecretKey::from_pkcs8_der(der) {
            return Ok(Self::from_coset(p256_secret_to_cose(&sk)));
        }

        #[allow(unused_imports)]
        use ed25519_dalek::pkcs8::DecodePrivateKey as _;
        if let Ok(sk) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
            return Ok(Self::from_coset(ed25519_signing_to_cose(&sk)));
        }

        Err(OffboardError::Other("unsupported DER key format".into()))
    }

    /// Export the public key as CBOR COSE_Key bytes (without private material).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let mut pub_key = self.inner.clone();
        // Remove the private key parameter (label -4 for EC2 `d`, -4 for OKP `d`)
        pub_key.params.retain(|(label, _)| *label != Label::Int(-4));
        pub_key.to_vec().unwrap_or_default()
    }

    /// Export the full key (including private material) as CBOR COSE_Key bytes.
    pub fn to_cose_key_bytes(&self) -> Vec<u8> {
        self.inner.clone().to_vec().unwrap_or_default()
    }

    /// Get the key identifier.
    pub fn key_id(&self) -> &[u8] {
        &self.inner.key_id
    }

    /// Set the key identifier.
    pub fn set_key_id(&mut self, kid: Vec<u8>) {
        self.inner.key_id = kid;
    }

    /// Returns true if this is an EC2 (P-256) key (signing or ECDH).
    pub fn is_ec2(&self) -> bool {
        matches!(self.inner.kty, coset::KeyType::Assigned(iana::KeyType::EC2))
    }

    /// Returns true if this is a symmetric key (e.g., A128KW).
    pub fn is_symmetric(&self) -> bool {
        matches!(
            self.inner.kty,
            coset::KeyType::Assigned(iana::KeyType::Symmetric)
        )
    }

    /// Access the inner coset key.
    pub(crate) fn inner(&self) -> &coset::CoseKey {
        &self.inner
    }

    /// Extract the EC2 / P-256 private scalar `d` and return a
    /// `p256::ecdsa::SigningKey`. Errors out if this key isn't an EC2
    /// key with a private component.
    pub fn to_p256_signing_key(&self) -> Result<p256::ecdsa::SigningKey, OffboardError> {
        if !self.is_ec2() {
            return Err(OffboardError::Other(
                "expected EC2 P-256 key for signing".into(),
            ));
        }
        let d = extract_label_bytes(&self.inner, -4)
            .ok_or_else(|| OffboardError::Other("missing private scalar `d`".into()))?;
        p256::ecdsa::SigningKey::from_bytes(d.as_slice().into())
            .map_err(|e| OffboardError::Other(format!("invalid P-256 signing key bytes: {e}")))
    }

    /// Extract the EC2 / P-256 public coordinates `(x, y)`. Each
    /// 32 bytes. Errors out if this key isn't an EC2 key or the
    /// coords aren't the expected length.
    pub fn ec2_public_xy(&self) -> Result<(Vec<u8>, Vec<u8>), OffboardError> {
        if !self.is_ec2() {
            return Err(OffboardError::Other("expected EC2 P-256 key".into()));
        }
        let x = extract_label_bytes(&self.inner, -2)
            .ok_or_else(|| OffboardError::Other("missing EC2 `x` coordinate".into()))?;
        let y = extract_label_bytes(&self.inner, -3)
            .ok_or_else(|| OffboardError::Other("missing EC2 `y` coordinate".into()))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(OffboardError::Other(format!(
                "EC2 coords must be 32 bytes each (got x={}, y={})",
                x.len(),
                y.len()
            )));
        }
        Ok((x, y))
    }
}

fn extract_label_bytes(key: &coset::CoseKey, label: i64) -> Option<Vec<u8>> {
    for (l, v) in &key.params {
        if let Label::Int(li) = l {
            if *li == label {
                if let ciborium::value::Value::Bytes(b) = v {
                    return Some(b.clone());
                }
            }
        }
    }
    None
}

/// Build a coset::CoseKey from a P-256 secret key.
pub(crate) fn p256_secret_to_cose(sk: &p256::SecretKey) -> coset::CoseKey {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pk = sk.public_key().to_encoded_point(false);
    let x = pk.x().unwrap().as_slice().to_vec();
    let y = pk.y().unwrap().as_slice().to_vec();
    let d = sk.to_bytes().to_vec();

    coset::CoseKeyBuilder::new_ec2_priv_key(iana::EllipticCurve::P_256, x, y, d)
        .algorithm(iana::Algorithm::ES256)
        .build()
}

/// Build a coset::CoseKey from a P-256 public key only.
#[allow(dead_code)]
pub(crate) fn p256_public_to_cose(pk: &p256::PublicKey) -> coset::CoseKey {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let pt = pk.to_encoded_point(false);
    let x = pt.x().unwrap().as_slice().to_vec();
    let y = pt.y().unwrap().as_slice().to_vec();

    coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y)
        .algorithm(iana::Algorithm::ES256)
        .build()
}

/// Build a coset::CoseKey from an Ed25519 signing key.
pub(crate) fn ed25519_signing_to_cose(sk: &ed25519_dalek::SigningKey) -> coset::CoseKey {
    let x = sk.verifying_key().to_bytes().to_vec();
    let d = sk.to_bytes().to_vec();

    coset::CoseKeyBuilder::new_okp_key()
        .algorithm(iana::Algorithm::EdDSA)
        .param(
            iana::OkpKeyParameter::Crv as i64,
            ciborium::value::Value::from(iana::EllipticCurve::Ed25519 as i64),
        )
        .param(
            iana::OkpKeyParameter::X as i64,
            ciborium::value::Value::Bytes(x),
        )
        .param(
            iana::OkpKeyParameter::D as i64,
            ciborium::value::Value::Bytes(d),
        )
        .build()
}
