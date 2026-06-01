//! Streaming SUIT payload decryptor (AES-128-GCM).
//!
//! Parses COSE_Encrypt from the manifest's encryption-info parameter,
//! unwraps the CEK (A128KW or ECDH-ES+A128KW), then provides a streaming
//! AES-128-GCM decryption interface.
//!
//! CEK unwrap is delegated through the [`KeyUnwrap`] trait so the device
//! private key can stay inside a hardware HSM (HSE/TPM/etc.) — the
//! caller only ever sees the ephemeral per-payload CEK. For dev/test
//! and unit tests, [`InMemoryKeyUnwrap`] keeps the original "device
//! key is a `CoseKey` in memory" behavior available.

use coset::CborSerializable;

use crate::error::Sum2Error;
use crate::manifest::Manifest;
use sumo_crypto::cose_key;
use sumo_crypto::streaming::StreamingAeadDecryptor;
use sumo_crypto::CryptoBackend;

/// CEK-unwrap surface a decryptor calls. Implementors hold the device
/// private key in whatever way they like — in memory for dev/test, or
/// inside an HSM/HSE for production. Only the unwrapped 16-byte CEK is
/// returned; the device key itself never crosses the trait boundary.
pub trait KeyUnwrap {
    /// AES-KW direct unwrap. The implementor's device key is the
    /// symmetric KEK; `wrapped_cek` is the RFC-3394 wrapped output.
    fn unwrap_cek_a128kw(&self, wrapped_cek: &[u8]) -> Result<Vec<u8>, Sum2Error>;

    /// ECDH-ES+A128KW unwrap.
    ///
    /// `ephem_pub` is the sender's ephemeral EC-P256 public key in
    /// uncompressed SEC1 form (65 bytes, leading 0x04). `wrapped_cek`
    /// is the A128KW-wrapped CEK. `recipient_protected` is the COSE
    /// protected header of the recipient — fed into the KDF context.
    fn unwrap_cek_ecdh_es(
        &self,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, Sum2Error>;
}

/// Dev/test [`KeyUnwrap`] impl that holds the device key as bytes in
/// process memory. Suitable for unit tests, simulator setups, and any
/// non-hardware scenario where the device key is just a file. **Not**
/// suitable for production on real HSE — use an HSM-backed implementor
/// instead.
pub struct InMemoryKeyUnwrap<'a> {
    pub device_key: &'a coset::CoseKey,
    pub crypto: &'a dyn CryptoBackend,
}

impl<'a> InMemoryKeyUnwrap<'a> {
    pub fn new(device_key: &'a coset::CoseKey, crypto: &'a dyn CryptoBackend) -> Self {
        Self { device_key, crypto }
    }
}

impl<'a> KeyUnwrap for InMemoryKeyUnwrap<'a> {
    fn unwrap_cek_a128kw(&self, wrapped_cek: &[u8]) -> Result<Vec<u8>, Sum2Error> {
        let k = extract_symmetric_key(self.device_key)?;
        self.crypto
            .aes_kw_unwrap(&k, wrapped_cek)
            .map_err(|_| Sum2Error::DecryptFailed)
    }

    fn unwrap_cek_ecdh_es(
        &self,
        ephem_pub: &[u8],
        wrapped_cek: &[u8],
        recipient_protected: &[u8],
    ) -> Result<Vec<u8>, Sum2Error> {
        let dev_ec2 =
            cose_key::extract_ec2(self.device_key).map_err(|_| Sum2Error::DecryptFailed)?;
        let dev_d = dev_ec2.d.ok_or(Sum2Error::DecryptFailed)?;
        sumo_crypto::ecdh_es::ecdh_es_a128kw_unwrap(
            self.crypto,
            &dev_d,
            ephem_pub,
            wrapped_cek,
            recipient_protected,
        )
        .map_err(|_| Sum2Error::DecryptFailed)
    }
}

/// Streaming decryptor for encrypted SUIT payloads.
pub struct StreamingDecryptor {
    inner: Box<dyn StreamingAeadDecryptor>,
}

impl StreamingDecryptor {
    /// Create a decryptor from a manifest's encryption info and a
    /// caller-supplied [`KeyUnwrap`] (the abstraction over "wherever
    /// the device private key lives — in memory or in an HSM").
    ///
    /// Parses the COSE_Encrypt structure, determines the key-agreement
    /// algorithm (A128KW or ECDH-ES+A128KW), asks `key_unwrap` to
    /// produce the 16-byte CEK, and initializes streaming AES-128-GCM
    /// decryption. The device key itself never appears here; only the
    /// ephemeral CEK is materialized.
    pub fn new(
        manifest: &Manifest,
        component_index: usize,
        key_unwrap: &dyn KeyUnwrap,
        crypto: &dyn CryptoBackend,
    ) -> Result<Self, Sum2Error> {
        let enc_info = manifest
            .encryption_info(component_index)
            .ok_or(Sum2Error::DecryptFailed)?;

        // Parse COSE_Encrypt
        let parsed = parse_cose_encrypt(enc_info).map_err(|_| Sum2Error::DecryptFailed)?;

        // Unwrap CEK via the caller's abstraction. Different impls
        // route this to in-memory crypto, vHSM, HSE, etc.
        let cek = unwrap_cek_via(&parsed, key_unwrap)?;
        if cek.len() != 16 {
            return Err(Sum2Error::DecryptFailed);
        }
        let mut cek_arr = [0u8; 16];
        cek_arr.copy_from_slice(&cek);

        let mut iv_arr = [0u8; 12];
        if parsed.iv.len() != 12 {
            return Err(Sum2Error::DecryptFailed);
        }
        iv_arr.copy_from_slice(&parsed.iv);

        let inner = crypto
            .aes_gcm_decrypt_stream(&cek_arr, &iv_arr, &[])
            .map_err(|_| Sum2Error::DecryptFailed)?;

        Ok(Self { inner })
    }

    /// Feed a chunk of ciphertext. Returns bytes of plaintext produced.
    pub fn update(&mut self, ciphertext: &[u8], plaintext: &mut [u8]) -> Result<usize, Sum2Error> {
        self.inner
            .update(ciphertext, plaintext)
            .map_err(|_| Sum2Error::DecryptFailed)
    }

    /// Finalize decryption and verify the GCM tag.
    pub fn finalize(&mut self, plaintext: &mut [u8]) -> Result<usize, Sum2Error> {
        self.inner
            .finalize(plaintext)
            .map_err(|_| Sum2Error::DecryptFailed)
    }
}

// --- COSE_Encrypt parsing ---

struct ParsedCoseEncrypt {
    iv: Vec<u8>,
    recipient_alg: i64,
    recipient_protected: Vec<u8>,
    wrapped_cek: Vec<u8>,
    /// Ephemeral public key (for ECDH-ES), extracted from recipient unprotected header
    ephemeral_key: Option<coset::CoseKey>,
}

/// Parse a COSE_Encrypt CBOR structure.
///
/// ```text
/// COSE_Encrypt = [
///   protected,     // bstr
///   unprotected,   // map {5: IV}
///   ciphertext,    // null (detached)
///   recipients     // [COSE_recipient, ...]
/// ]
/// ```
fn parse_cose_encrypt(data: &[u8]) -> Result<ParsedCoseEncrypt, Sum2Error> {
    use ciborium::value::Value;

    let value: Value = ciborium::de::from_reader(data).map_err(|_| Sum2Error::DecryptFailed)?;

    // May be tagged (tag 96) or untagged
    let arr = match &value {
        Value::Tag(96, inner) => match inner.as_ref() {
            Value::Array(a) => a,
            _ => return Err(Sum2Error::DecryptFailed),
        },
        Value::Array(a) => a,
        _ => return Err(Sum2Error::DecryptFailed),
    };

    if arr.len() < 4 {
        return Err(Sum2Error::DecryptFailed);
    }

    // [0] protected header (bstr) — we don't need it for CEK unwrap
    // [1] unprotected header (map) — extract IV (label 5)
    let iv = extract_iv_from_map(&arr[1])?;

    // [2] ciphertext — null (detached)
    // [3] recipients array
    let recipients = match &arr[3] {
        Value::Array(a) => a,
        _ => return Err(Sum2Error::DecryptFailed),
    };

    if recipients.is_empty() {
        return Err(Sum2Error::DecryptFailed);
    }

    // First recipient
    let rcpt = match &recipients[0] {
        Value::Array(a) => a,
        _ => return Err(Sum2Error::DecryptFailed),
    };
    if rcpt.len() < 3 {
        return Err(Sum2Error::DecryptFailed);
    }

    // recipient[0]: protected header bstr — may contain algorithm (ECDH-ES case)
    let rcpt_prot_bytes = match &rcpt[0] {
        Value::Bytes(b) => b.clone(),
        _ => Vec::new(),
    };
    let mut recipient_alg: i64 = 0;
    if !rcpt_prot_bytes.is_empty() {
        if let Ok(prot_map) = ciborium::de::from_reader::<Value, _>(rcpt_prot_bytes.as_slice()) {
            if let Value::Map(entries) = &prot_map {
                for (k, v) in entries {
                    if cbor_to_i64(k) == Some(1) {
                        if let Some(alg) = cbor_to_i64(v) {
                            recipient_alg = alg;
                        }
                    }
                }
            }
        }
    }

    // recipient[1]: unprotected header map — get alg (A128KW), kid, ephemeral key (-1)
    let mut ephemeral_key = None;
    if let Value::Map(entries) = &rcpt[1] {
        for (k, v) in entries {
            let label = cbor_to_i64(k).unwrap_or(0);
            if label == 1 && recipient_alg == 0 {
                // algorithm — only if not in protected
                if let Some(alg) = cbor_to_i64(v) {
                    recipient_alg = alg;
                }
            }
            if label == -1 {
                // COSE_Key (ephemeral public key for ECDH)
                if let Value::Map(_) = v {
                    // Re-serialize and parse as CoseKey
                    let mut buf = Vec::new();
                    if ciborium::ser::into_writer(v, &mut buf).is_ok() {
                        if let Ok(key) = coset::CoseKey::from_slice(&buf) {
                            ephemeral_key = Some(key);
                        }
                    }
                }
            }
        }
    }

    // recipient[2]: ciphertext — the wrapped CEK
    let wrapped_cek = match &rcpt[2] {
        Value::Bytes(b) => b.clone(),
        _ => return Err(Sum2Error::DecryptFailed),
    };

    Ok(ParsedCoseEncrypt {
        iv,
        recipient_alg,
        recipient_protected: rcpt_prot_bytes,
        wrapped_cek,
        ephemeral_key,
    })
}

fn extract_iv_from_map(value: &ciborium::value::Value) -> Result<Vec<u8>, Sum2Error> {
    use ciborium::value::Value;
    match value {
        Value::Map(entries) => {
            for (k, v) in entries {
                if cbor_to_i64(k) == Some(5) {
                    if let Value::Bytes(b) = v {
                        return Ok(b.clone());
                    }
                }
            }
            Err(Sum2Error::DecryptFailed)
        }
        _ => Err(Sum2Error::DecryptFailed),
    }
}

fn cbor_to_i64(v: &ciborium::value::Value) -> Option<i64> {
    match v {
        ciborium::value::Value::Integer(i) => Some(i128::from(*i) as i64),
        _ => None,
    }
}

// --- CEK unwrapping ---

/// Parse the COSE_Encrypt's recipient algorithm and dispatch to the
/// matching method on the caller's [`KeyUnwrap`] impl. The dispatcher
/// is responsible for extracting the ephemeral public key from the
/// recipient when the alg is ECDH-ES+A128KW — the unwrap implementor
/// only needs to know how to do the math, not the COSE structure.
fn unwrap_cek_via(
    parsed: &ParsedCoseEncrypt,
    key_unwrap: &dyn KeyUnwrap,
) -> Result<Vec<u8>, Sum2Error> {
    match parsed.recipient_alg {
        cose_key::COSE_ALG_A128KW => key_unwrap.unwrap_cek_a128kw(&parsed.wrapped_cek),
        cose_key::COSE_ALG_ECDH_ES_A128KW => {
            let ephemeral = parsed
                .ephemeral_key
                .as_ref()
                .ok_or(Sum2Error::DecryptFailed)?;
            let ec2 = cose_key::extract_ec2(ephemeral).map_err(|_| Sum2Error::DecryptFailed)?;
            let mut ephem_pub = [0u8; 65];
            ephem_pub[0] = 0x04;
            ephem_pub[1..33].copy_from_slice(&ec2.x);
            ephem_pub[33..65].copy_from_slice(&ec2.y);
            key_unwrap.unwrap_cek_ecdh_es(
                &ephem_pub,
                &parsed.wrapped_cek,
                &parsed.recipient_protected,
            )
        }
        _ => Err(Sum2Error::Unsupported),
    }
}

fn extract_symmetric_key(key: &coset::CoseKey) -> Result<Vec<u8>, Sum2Error> {
    // For symmetric keys, the key value is in parameter label -1 (COSE_KEY_K = -1 for symmetric)
    // Actually for symmetric keys it's label -1 in the key map
    for (label, value) in &key.params {
        if let coset::Label::Int(-1) = label {
            if let ciborium::value::Value::Bytes(b) = value {
                return Ok(b.clone());
            }
        }
    }
    Err(Sum2Error::DecryptFailed)
}
