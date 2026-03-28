//! ECDH-ES+A128KW key agreement and key wrapping.
//!
//! Implements the COSE_KDF_Context construction per RFC 9053 §5.3 and
//! the SUIT firmware encryption profile (draft-ietf-suit-firmware-encryption).

use crate::error::CryptoError;
use crate::traits::CryptoBackend;

/// Build the COSE_KDF_Context CBOR for ECDH-ES+A128KW.
///
/// ```text
/// COSE_KDF_Context = [
///   AlgorithmID: -3,              // A128KW
///   PartyUInfo: [null, null, null],
///   PartyVInfo: [null, null, null],
///   SuppPubInfo: [128, protected_header, "SUIT Payload Encryption"]
/// ]
/// ```
fn build_kdf_context(protected: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use ciborium::value::{Integer, Value};

    let context = Value::Array(vec![
        // AlgorithmID: A128KW = -3
        Value::Integer(Integer::from(-3i64)),
        // PartyUInfo: [null, null, null]
        Value::Array(vec![Value::Null, Value::Null, Value::Null]),
        // PartyVInfo: [null, null, null]
        Value::Array(vec![Value::Null, Value::Null, Value::Null]),
        // SuppPubInfo: [keyDataLength=128, protected, "SUIT Payload Encryption"]
        Value::Array(vec![
            Value::Integer(Integer::from(128i64)),
            Value::Bytes(protected.to_vec()),
            Value::Bytes(b"SUIT Payload Encryption".to_vec()),
        ]),
    ]);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&context, &mut buf)
        .map_err(|_| CryptoError::KeyAgreementFailed)?;
    Ok(buf)
}

/// Perform ECDH-ES+A128KW key unwrapping (onboard / decryption side).
///
/// 1. ECDH between device private key and ephemeral public key → shared secret
/// 2. HKDF-SHA256(shared_secret, salt="", info=COSE_KDF_Context) → 16-byte KEK
/// 3. AES-KW unwrap CEK using KEK
///
/// # Parameters
/// - `device_private_key`: 32-byte P-256 scalar (d)
/// - `ephemeral_public_key`: 65-byte uncompressed point (04 || x || y) or 64-byte (x || y)
/// - `wrapped_cek`: AES-KW wrapped CEK (24 bytes for 16-byte CEK)
/// - `protected`: recipient protected header bytes (used in KDF context)
pub fn ecdh_es_a128kw_unwrap(
    crypto: &dyn CryptoBackend,
    device_private_key: &[u8],
    ephemeral_public_key: &[u8],
    wrapped_cek: &[u8],
    protected: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // 1. ECDH key agreement
    let shared_secret = crypto.ecdh_p256(device_private_key, ephemeral_public_key)?;

    // 2. Build KDF context and derive KEK
    let kdf_context = build_kdf_context(protected)?;
    let kek = crypto.hkdf_sha256(&shared_secret, &[], &kdf_context, 16)?;

    // 3. AES-KW unwrap CEK
    crypto.aes_kw_unwrap(&kek, wrapped_cek)
}

/// Perform ECDH-ES+A128KW key wrapping (offboard / encryption side).
///
/// 1. Generate ephemeral P-256 keypair
/// 2. ECDH between ephemeral private key and recipient public key → shared secret
/// 3. HKDF-SHA256(shared_secret, salt="", info=COSE_KDF_Context) → 16-byte KEK
/// 4. AES-KW wrap CEK using KEK
///
/// # Parameters
/// - `sender_private_key`: 32-byte ephemeral P-256 scalar (d)
/// - `recipient_public_key`: 65-byte uncompressed point (04 || x || y) or 64-byte (x || y)
/// - `cek`: 16-byte content encryption key to wrap
/// - `protected`: recipient protected header bytes (used in KDF context)
///
/// # Returns
/// `(wrapped_cek, sender_public_key_uncompressed)` — the wrapped CEK and the
/// ephemeral public key to include in the COSE_Encrypt recipient header.
pub fn ecdh_es_a128kw_wrap(
    crypto: &dyn CryptoBackend,
    sender_private_key: &[u8],
    recipient_public_key: &[u8],
    cek: &[u8],
    protected: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // 1. ECDH key agreement
    let shared_secret = crypto.ecdh_p256(sender_private_key, recipient_public_key)?;

    // 2. Build KDF context and derive KEK
    let kdf_context = build_kdf_context(protected)?;
    let kek = crypto.hkdf_sha256(&shared_secret, &[], &kdf_context, 16)?;

    // 3. AES-KW wrap CEK
    crypto.aes_kw_wrap(&kek, cek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RustCryptoBackend;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn ecdh_es_wrap_unwrap_roundtrip() {
        let crypto = RustCryptoBackend::new();

        // Generate an ephemeral sender keypair (for wrapping)
        let mut rng_buf = [0u8; 32];
        getrandom::getrandom(&mut rng_buf).unwrap();
        let sender_sk = p256::SecretKey::from_bytes((&rng_buf).into()).unwrap();
        let sender_pk_point = sender_sk.public_key().to_encoded_point(false);
        let sender_d = sender_sk.to_bytes();

        // Generate recipient keypair
        getrandom::getrandom(&mut rng_buf).unwrap();
        let recipient_sk = p256::SecretKey::from_bytes((&rng_buf).into()).unwrap();
        let recipient_pk_point = recipient_sk.public_key().to_encoded_point(false);
        let recipient_d = recipient_sk.to_bytes();

        let cek = [0x42u8; 16];
        let protected = b"\xa1\x01\x38\x1c"; // {1: -29} = ECDH-ES+A128KW

        // Wrap
        let wrapped = ecdh_es_a128kw_wrap(
            &crypto,
            sender_d.as_slice(),
            recipient_pk_point.as_bytes(),
            &cek,
            protected,
        )
        .unwrap();
        assert_eq!(wrapped.len(), 24); // 16 + 8

        // Unwrap with recipient's private key and sender's public key
        let unwrapped = ecdh_es_a128kw_unwrap(
            &crypto,
            recipient_d.as_slice(),
            sender_pk_point.as_bytes(),
            &wrapped,
            protected,
        )
        .unwrap();

        assert_eq!(unwrapped, cek);
    }
}
