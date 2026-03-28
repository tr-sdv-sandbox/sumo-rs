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

/// True streaming AES-128-GCM decryptor.
///
/// Uses AES-CTR for streaming decryption and GHASH for incremental
/// authentication. Tail-buffers 16 bytes to separate the GCM tag
/// from ciphertext. On finalize, verifies the GCM authentication tag.
///
/// Note: plaintext is output before tag verification. Callers must
/// discard output if finalize() returns an error.
struct AesGcmStreamDecryptor {
    /// AES cipher for encrypting counter blocks
    cipher: aes::Aes128,
    /// Initial counter block (J0 = IV || 0x00000001) for final tag XOR
    j0: [u8; 16],
    /// Current counter (starts at 2 for payload)
    counter: u32,
    /// IV for counter block construction
    iv: [u8; 12],
    /// GHASH state for authentication
    ghash: ghash::GHash,
    /// Tail buffer: holds the last 16 bytes which may be the GCM tag
    tail: [u8; 16],
    /// How many valid bytes are in the tail buffer
    tail_len: usize,
    /// Total ciphertext bytes processed (excluding tag)
    ct_bytes: u64,
    /// Partial block buffer for 16-byte alignment of GHASH
    ghash_partial: [u8; 16],
    /// Bytes in ghash_partial
    ghash_partial_len: usize,
    /// Remaining keystream bytes from the current CTR block
    keystream_buf: [u8; 16],
    /// Offset into keystream_buf (how many bytes already consumed)
    keystream_offset: usize,
}

impl AesGcmStreamDecryptor {
    fn new(key: [u8; 16], iv: [u8; 12]) -> Self {
        use aes::cipher::KeyInit;

        let cipher = aes::Aes128::new(&key.into());

        // Compute H = AES(K, 0^128) for GHASH
        let mut h_block = aes::Block::default();
        aes::cipher::BlockEncrypt::encrypt_block(&cipher, &mut h_block);

        let ghash = ghash::GHash::new(&h_block);

        // J0 = IV || 0x00000001
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&iv);
        j0[15] = 1;

        Self {
            cipher,
            j0,
            counter: 2, // GCM payload counter starts at 2
            iv,
            ghash,
            tail: [0u8; 16],
            tail_len: 0,
            ct_bytes: 0,
            ghash_partial: [0u8; 16],
            ghash_partial_len: 0,
            keystream_buf: [0u8; 16],
            keystream_offset: 16, // 16 = empty (need new block)
        }
    }

    /// Decrypt arbitrary-length ciphertext using AES-CTR, handling partial blocks.
    fn ctr_decrypt(&mut self, ct: &[u8], pt_out: &mut [u8]) {
        let mut ct_pos = 0;
        let mut pt_pos = 0;

        while ct_pos < ct.len() {
            // Generate new keystream block if needed
            if self.keystream_offset >= 16 {
                let mut ctr_block = aes::Block::default();
                ctr_block[..12].copy_from_slice(&self.iv);
                ctr_block[12..16].copy_from_slice(&self.counter.to_be_bytes());
                self.counter = self.counter.wrapping_add(1);
                aes::cipher::BlockEncrypt::encrypt_block(&self.cipher, &mut ctr_block);
                self.keystream_buf = ctr_block.into();
                self.keystream_offset = 0;
            }

            // XOR as many bytes as possible from current keystream block
            let ks_remaining = 16 - self.keystream_offset;
            let ct_remaining = ct.len() - ct_pos;
            let n = ks_remaining.min(ct_remaining);

            for i in 0..n {
                pt_out[pt_pos + i] = ct[ct_pos + i] ^ self.keystream_buf[self.keystream_offset + i];
            }

            self.keystream_offset += n;
            ct_pos += n;
            pt_pos += n;
        }
    }

    /// Feed ciphertext bytes into GHASH (must be 16-byte aligned blocks).
    fn ghash_feed(&mut self, data: &[u8]) {
        use ghash::universal_hash::UniversalHash;

        let mut pos = 0;

        // First, fill partial buffer
        if self.ghash_partial_len > 0 {
            let need = 16 - self.ghash_partial_len;
            let take = data.len().min(need);
            self.ghash_partial[self.ghash_partial_len..self.ghash_partial_len + take]
                .copy_from_slice(&data[..take]);
            self.ghash_partial_len += take;
            pos = take;

            if self.ghash_partial_len == 16 {
                let block = ghash::Block::from(self.ghash_partial);
                self.ghash.update(&[block]);
                self.ghash_partial_len = 0;
            } else {
                return;
            }
        }

        // Process full 16-byte blocks
        while pos + 16 <= data.len() {
            let block: [u8; 16] = data[pos..pos + 16].try_into().unwrap();
            self.ghash.update(&[ghash::Block::from(block)]);
            pos += 16;
        }

        // Save remainder
        if pos < data.len() {
            let remain = data.len() - pos;
            self.ghash_partial[..remain].copy_from_slice(&data[pos..]);
            self.ghash_partial_len = remain;
        }
    }
}

impl StreamingAeadDecryptor for AesGcmStreamDecryptor {
    fn update(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<usize, CryptoError> {
        if ciphertext.is_empty() {
            return Ok(0);
        }

        // Combine old tail + new data into a working buffer.
        // The last 16 bytes are the new tail (potential GCM tag).
        // Everything before that is definite ciphertext to decrypt now.
        let mut combined = Vec::with_capacity(self.tail_len + ciphertext.len());
        combined.extend_from_slice(&self.tail[..self.tail_len]);
        combined.extend_from_slice(ciphertext);

        if combined.len() <= 16 {
            // Not enough data yet — save as tail
            self.tail[..combined.len()].copy_from_slice(&combined);
            self.tail_len = combined.len();
            return Ok(0);
        }

        let definite_ct_len = combined.len() - 16;

        // Decrypt definite ciphertext
        let definite_ct = &combined[..definite_ct_len];
        self.ghash_feed(definite_ct);
        self.ct_bytes += definite_ct_len as u64;
        self.ctr_decrypt(definite_ct, &mut plaintext[..definite_ct_len]);

        // Save new tail (last 16 bytes)
        self.tail.copy_from_slice(&combined[definite_ct_len..]);
        self.tail_len = 16;

        Ok(definite_ct_len)
    }

    fn finalize(&mut self, _plaintext: &mut [u8]) -> Result<usize, CryptoError> {
        use ghash::universal_hash::UniversalHash;

        if self.tail_len < 16 {
            return Err(CryptoError::DecryptionFailed);
        }

        // Flush any partial GHASH block (pad with zeros)
        if self.ghash_partial_len > 0 {
            // Pad to 16 bytes
            self.ghash_partial[self.ghash_partial_len..].fill(0);
            let block = ghash::Block::from(self.ghash_partial);
            self.ghash.update(&[block]);
            self.ghash_partial_len = 0;
        }

        // Feed length block: [0^64 || len(C) in bits as u64 BE]
        // No AAD, so aad_bits = 0
        let ct_bits = self.ct_bytes * 8;
        let mut len_block = [0u8; 16];
        len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
        self.ghash.update(&[ghash::Block::from(len_block)]);

        // Compute S = GHASH finalize
        let s = self.ghash.clone().finalize();

        // Compute tag = S XOR E(K, J0)
        let mut j0_enc = aes::Block::from(self.j0);
        aes::cipher::BlockEncrypt::encrypt_block(&self.cipher, &mut j0_enc);

        let mut computed_tag = [0u8; 16];
        for i in 0..16 {
            computed_tag[i] = s.as_slice()[i] ^ j0_enc[i];
        }

        // Compare with tail buffer (the received tag)
        let tags_match = computed_tag
            .iter()
            .zip(self.tail.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));

        if tags_match != 0 {
            return Err(CryptoError::DecryptionFailed);
        }

        Ok(0) // All plaintext was already output during update()
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
        let mut pt = vec![0u8; plaintext.len() + 16];
        let n = dec.update(&ct, &mut pt).unwrap();
        let n2 = dec.finalize(&mut pt[n..]).unwrap();
        assert_eq!(&pt[..n + n2], plaintext);
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
