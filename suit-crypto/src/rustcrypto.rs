//! RustCrypto-based CryptoBackend implementation.

use crate::cose_key;
use crate::error::CryptoError;
use crate::streaming::{StreamingAeadDecryptor, StreamingHash};
use crate::traits::CryptoBackend;

use sha2::Digest;

/// CryptoBackend implementation using RustCrypto crates.
pub struct RustCryptoBackend;

impl RustCryptoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustCryptoBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoBackend for RustCryptoBackend {
    fn verify_sign1(
        &self,
        key: &coset::CoseKey,
        protected: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let alg = cose_key::key_algorithm(key);
        match alg {
            Some(cose_key::COSE_ALG_ES256) => {
                verify_es256(key, protected, payload, signature)
            }
            Some(cose_key::COSE_ALG_EDDSA) => {
                verify_eddsa(key, protected, payload, signature)
            }
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    fn sign(
        &self,
        key: &coset::CoseKey,
        protected: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let alg = cose_key::key_algorithm(key);
        match alg {
            Some(cose_key::COSE_ALG_ES256) => sign_es256(key, protected, payload),
            Some(cose_key::COSE_ALG_EDDSA) => sign_eddsa(key, protected, payload),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn sha256_streaming(&self) -> Box<dyn StreamingHash> {
        Box::new(Sha256Stream(sha2::Sha256::new()))
    }

    fn ecdh_p256(
        &self,
        private_key: &[u8],
        peer_public_key: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        // Parse private key (32 bytes scalar)
        let secret = p256::SecretKey::from_bytes(private_key.into())
            .map_err(|_| CryptoError::InvalidKey)?;

        // Parse peer public key (uncompressed point: 04 || x || y, or just x || y)
        let peer_point = if peer_public_key.len() == 65 && peer_public_key[0] == 0x04 {
            p256::EncodedPoint::from_bytes(peer_public_key)
                .map_err(|_| CryptoError::InvalidKey)?
        } else if peer_public_key.len() == 64 {
            // x || y format — prepend 04
            let mut uncompressed = [0u8; 65];
            uncompressed[0] = 0x04;
            uncompressed[1..].copy_from_slice(peer_public_key);
            p256::EncodedPoint::from_bytes(&uncompressed)
                .map_err(|_| CryptoError::InvalidKey)?
        } else {
            return Err(CryptoError::InvalidKey);
        };

        let peer_public = p256::PublicKey::from_encoded_point(&peer_point)
            .into_option()
            .ok_or(CryptoError::InvalidKey)?;

        // Perform ECDH
        let shared_secret = p256::ecdh::diffie_hellman(
            secret.to_nonzero_scalar(),
            peer_public.as_affine(),
        );

        Ok(shared_secret.raw_secret_bytes().to_vec())
    }

    fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        use hkdf::Hkdf;

        let salt = if salt.is_empty() { None } else { Some(salt) };
        let hk = Hkdf::<sha2::Sha256>::new(salt, ikm);
        let mut okm = vec![0u8; output_len];
        hk.expand(info, &mut okm)
            .map_err(|_| CryptoError::InvalidLength)?;
        Ok(okm)
    }

    fn aes_kw_unwrap(&self, kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_kw::Kek;

        if kek.len() != 16 {
            return Err(CryptoError::InvalidLength);
        }
        let kek_arr: [u8; 16] = kek.try_into().unwrap();
        let kek = Kek::<aes::Aes128>::from(kek_arr);

        let mut output = vec![0u8; wrapped.len().saturating_sub(8)];
        kek.unwrap(wrapped, &mut output)
            .map_err(|_| CryptoError::KeyUnwrapFailed)?;
        Ok(output)
    }

    fn aes_kw_wrap(&self, kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aes_kw::Kek;

        if kek.len() != 16 {
            return Err(CryptoError::InvalidLength);
        }
        let kek_arr: [u8; 16] = kek.try_into().unwrap();
        let kek = Kek::<aes::Aes128>::from(kek_arr);

        let mut output = vec![0u8; plaintext.len() + 8];
        kek.wrap(plaintext, &mut output)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(output)
    }

    fn aes_gcm_decrypt_stream(
        &self,
        key: &[u8; 16],
        iv: &[u8; 12],
        _aad: &[u8],
    ) -> Result<Box<dyn StreamingAeadDecryptor>, CryptoError> {
        Ok(Box::new(AesGcmStreamDecryptor::new(*key, *iv)))
    }

    fn aes_gcm_encrypt(
        &self,
        key: &[u8; 16],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::{Aes128Gcm, KeyInit, AeadInPlace, Nonce};

        let cipher = Aes128Gcm::new(key.into());
        let nonce = Nonce::from_slice(iv);

        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    fn random_bytes(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        // Use getrandom for no_std compatible randomness
        getrandom::getrandom(buf).map_err(|_| CryptoError::EncryptionFailed)
    }
}

// --- ES256 (ECDSA P-256) ---

fn build_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    // Sig_structure = ["Signature1", protected, external_aad, payload]
    use ciborium::value::Value;
    let structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()), // external_aad
        Value::Bytes(payload.to_vec()),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&structure, &mut buf).unwrap();
    buf
}

fn verify_es256(
    key: &coset::CoseKey,
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let ec2 = cose_key::extract_ec2(key)?;

    // Build uncompressed point
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&ec2.x);
    point[33..65].copy_from_slice(&ec2.y);

    let vk = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| CryptoError::InvalidKey)?;

    // ES256 signature is r || s (32 + 32 = 64 bytes)
    let sig = Signature::from_bytes(signature.into())
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    let tbs = build_sig_structure(protected, payload);
    // Hash the TBS with SHA-256 (ECDSA does this internally)
    vk.verify(&tbs, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

fn sign_es256(
    key: &coset::CoseKey,
    protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use p256::ecdsa::{SigningKey, signature::Signer};

    let ec2 = cose_key::extract_ec2(key)?;
    let d = ec2.d.ok_or(CryptoError::InvalidKey)?;

    let sk = SigningKey::from_bytes(&d.into())
        .map_err(|_| CryptoError::InvalidKey)?;

    let tbs = build_sig_structure(protected, payload);
    let sig: p256::ecdsa::Signature = sk.sign(&tbs);

    // Return r || s (64 bytes)
    Ok(sig.to_bytes().to_vec())
}

// --- EdDSA (Ed25519) ---

fn verify_eddsa(
    key: &coset::CoseKey,
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use ed25519_dalek::{VerifyingKey as EdVerifyingKey, Signature as EdSignature, Verifier};

    let okp = cose_key::extract_okp(key)?;
    if okp.x.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let pub_bytes: [u8; 32] = okp.x.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let vk = EdVerifyingKey::from_bytes(&pub_bytes)
        .map_err(|_| CryptoError::InvalidKey)?;

    let sig = EdSignature::from_bytes(signature.try_into()
        .map_err(|_| CryptoError::SignatureVerificationFailed)?);

    let tbs = build_sig_structure(protected, payload);
    vk.verify(&tbs, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

fn sign_eddsa(
    key: &coset::CoseKey,
    protected: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use ed25519_dalek::{SigningKey as EdSigningKey, Signer};

    let okp = cose_key::extract_okp(key)?;
    let d = okp.d.ok_or(CryptoError::InvalidKey)?;
    if d.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let sk_bytes: [u8; 32] = d.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidKey)?;
    let sk = EdSigningKey::from_bytes(&sk_bytes);

    let tbs = build_sig_structure(protected, payload);
    let sig = sk.sign(&tbs);
    Ok(sig.to_bytes().to_vec())
}

// --- Streaming AES-128-GCM Decryptor ---

/// Streaming AES-128-GCM decryptor.
///
/// Buffers the last 16 bytes of ciphertext as the potential GCM tag.
/// On finalize, uses those 16 bytes as the authentication tag.
///
/// Note: aes-gcm crate doesn't support true streaming GCM. We accumulate
/// all ciphertext and decrypt on finalize. For memory-constrained use,
/// a CTR-mode streaming approach with deferred tag check would be needed.
struct AesGcmStreamDecryptor {
    key: [u8; 16],
    iv: [u8; 12],
    buffer: Vec<u8>,
}

impl AesGcmStreamDecryptor {
    fn new(key: [u8; 16], iv: [u8; 12]) -> Self {
        Self {
            key,
            iv,
            buffer: Vec::new(),
        }
    }
}

impl StreamingAeadDecryptor for AesGcmStreamDecryptor {
    fn update(&mut self, ciphertext: &[u8], _plaintext: &mut [u8]) -> Result<usize, CryptoError> {
        // Accumulate ciphertext — we'll decrypt all at once on finalize
        self.buffer.extend_from_slice(ciphertext);
        Ok(0) // No plaintext output yet
    }

    fn finalize(&mut self, plaintext: &mut [u8]) -> Result<usize, CryptoError> {
        use aes_gcm::{Aes128Gcm, KeyInit, AeadInPlace, Nonce, Tag};

        if self.buffer.len() < 16 {
            return Err(CryptoError::DecryptionFailed);
        }

        let tag_start = self.buffer.len() - 16;
        let tag_bytes: [u8; 16] = self.buffer[tag_start..].try_into().unwrap();
        let tag = Tag::from(tag_bytes);
        let mut ct = self.buffer[..tag_start].to_vec();

        let cipher = Aes128Gcm::new((&self.key).into());
        let nonce = Nonce::from_slice(&self.iv);

        cipher.decrypt_in_place_detached(nonce, &[], &mut ct, &tag)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let len = ct.len().min(plaintext.len());
        plaintext[..len].copy_from_slice(&ct[..len]);
        Ok(len)
    }
}

// --- Streaming SHA-256 ---

struct Sha256Stream(sha2::Sha256);

impl StreamingHash for Sha256Stream {
    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    fn finalize(self: Box<Self>) -> [u8; 32] {
        Digest::finalize(self.0).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CryptoBackend;

    #[test]
    fn sha256_known_value() {
        let backend = RustCryptoBackend::new();
        let hash = backend.sha256(b"hello");
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn aes_kw_roundtrip() {
        let backend = RustCryptoBackend::new();
        let kek = [0x42u8; 16];
        let cek = [0x01u8; 16];

        let wrapped = backend.aes_kw_wrap(&kek, &cek).unwrap();
        assert_eq!(wrapped.len(), 24); // 16 + 8

        let unwrapped = backend.aes_kw_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, cek);
    }

    #[test]
    fn aes_gcm_encrypt_decrypt() {
        let backend = RustCryptoBackend::new();
        let key = [0x42u8; 16];
        let iv = [0x01u8; 12];
        let plaintext = b"Hello SUIT firmware!";

        let ct = backend.aes_gcm_encrypt(&key, &iv, &[], plaintext).unwrap();
        assert_eq!(ct.len(), plaintext.len() + 16); // ciphertext + tag

        // Decrypt via streaming interface
        let mut dec = backend.aes_gcm_decrypt_stream(&key, &iv, &[]).unwrap();
        dec.update(&ct, &mut []).unwrap();
        let mut pt = vec![0u8; plaintext.len()];
        let len = dec.finalize(&mut pt).unwrap();
        assert_eq!(&pt[..len], plaintext);
    }

    #[test]
    fn hkdf_sha256_basic() {
        let backend = RustCryptoBackend::new();
        let ikm = [0x0b; 22];
        let salt = [0u8; 0];
        let info = [];
        let okm = backend.hkdf_sha256(&ikm, &salt, &info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }
}
