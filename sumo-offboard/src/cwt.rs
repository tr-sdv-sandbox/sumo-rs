//! Off-box CWT (CBOR Web Token, RFC 8392) minter for vHSM v3 certs.
//!
//! Mirrors `vhsm-ssd/src/cert.rs::mint_cwt` — same on-wire layout,
//! same claim set, same COSE_Sign1 structure — but signs with a
//! local `p256::ecdsa::SigningKey` instead of going through an HSM
//! adapter. Used by:
//!
//!   - Fleet provisioning systems that mint certs ahead of time
//!     (skip the in-box ENROLL round-trip).
//!   - Test rigs / dev tooling that need to issue ad-hoc certs.
//!   - Cert rotation tooling that doesn't tear down + re-enrol the
//!     guest.
//!
//! For the common operator path (single bootstrap-token consume on
//! first boot), use `bootstrap.rs` instead and let the daemon mint
//! the cert in-box via ENROLL — that flow doesn't expose the
//! `ecu-signing` private key to off-box tooling.
//!
//! The minted cert's claim set matches RFC 8392 §3.1.1 + RFC 8747 §3.2:
//!
//! | Claim | CBOR key | Value |
//! |-------|---------:|-------|
//! | iss | 1 | issuer string (operator-provided) |
//! | sub | 2 | principal name (vm_id) |
//! | aud | 3 | hard-coded `"vhsm-ssd"` |
//! | exp | 4 | Unix seconds |
//! | nbf | 5 | Unix seconds |
//! | iat | 6 | Unix seconds |
//! | cti | 7 | 16 random bytes |
//! | cnf | -65537 | `{ 1: <COSE_Key with EC2/P-256/x/y> }` |

use ciborium::value::{Integer, Value as CborValue};
use coset::iana::{Algorithm as CoseAlg, EllipticCurve as CoseEc};
use coset::{AsCborValue, CborSerializable, CoseKey, CoseSign1Builder, HeaderBuilder};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use rand::RngCore as _;

use crate::error::OffboardError;

const CLAIM_ISS: i64 = 1;
const CLAIM_SUB: i64 = 2;
const CLAIM_AUD: i64 = 3;
const CLAIM_EXP: i64 = 4;
const CLAIM_NBF: i64 = 5;
const CLAIM_IAT: i64 = 6;
const CLAIM_CTI: i64 = 7;
const CLAIM_CNF: i64 = -65537;

const COSE_KEY_EC2_CRV: i64 = -1;
const COSE_KEY_EC2_X: i64 = -2;
const COSE_KEY_EC2_Y: i64 = -3;

/// Hard-coded audience for vhsm-ssd-bound certs. Must match
/// `vhsm-ssd::cert::VHSM_AUDIENCE` exactly.
pub const VHSM_AUDIENCE: &str = "vhsm-ssd";

/// CWT validity window, in Unix seconds.
#[derive(Debug, Clone, Copy)]
pub struct ValidityWindow {
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
}

impl ValidityWindow {
    /// Convenience: `iat = now`, `nbf = now`, `exp = now + lifetime_secs`.
    pub fn from_now(now_unix: u64, lifetime_secs: u64) -> Self {
        Self {
            iat: now_unix,
            nbf: now_unix,
            exp: now_unix.saturating_add(lifetime_secs),
        }
    }
}

/// Mint a CWT signed by `signing_key`.
///
/// `cnf_pub_x` and `cnf_pub_y` are the 32-byte coordinates of the
/// guest's identity pubkey (P-256). Caller is responsible for
/// splitting the SEC1 `0x04 || x || y` representation if that's the
/// source format.
pub fn mint_cwt(
    signing_key: &SigningKey,
    subject: &str,
    issuer: &str,
    cnf_pub_x: &[u8],
    cnf_pub_y: &[u8],
    validity: ValidityWindow,
) -> Result<Vec<u8>, OffboardError> {
    if cnf_pub_x.len() != 32 || cnf_pub_y.len() != 32 {
        return Err(OffboardError::Other(format!(
            "cnf pubkey coordinates must be 32 bytes each (x={}, y={})",
            cnf_pub_x.len(),
            cnf_pub_y.len()
        )));
    }

    let cnf_cose_key = CoseKey {
        kty: coset::RegisteredLabel::Assigned(coset::iana::KeyType::EC2),
        alg: Some(coset::RegisteredLabelWithPrivate::Assigned(CoseAlg::ES256)),
        params: vec![
            (
                coset::Label::Int(COSE_KEY_EC2_CRV),
                CborValue::Integer(Integer::from(CoseEc::P_256 as i64)),
            ),
            (
                coset::Label::Int(COSE_KEY_EC2_X),
                CborValue::Bytes(cnf_pub_x.to_vec()),
            ),
            (
                coset::Label::Int(COSE_KEY_EC2_Y),
                CborValue::Bytes(cnf_pub_y.to_vec()),
            ),
        ],
        ..Default::default()
    };

    let cnf_val = cnf_cose_key
        .to_cbor_value()
        .map_err(|e| OffboardError::Other(format!("encode cnf COSE_Key: {e}")))?;
    let cnf_wrapped = CborValue::Map(vec![(CborValue::Integer(Integer::from(1i64)), cnf_val)]);

    let mut cti = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut cti);

    let claims = CborValue::Map(vec![
        (
            CborValue::Integer(Integer::from(CLAIM_ISS)),
            CborValue::Text(issuer.to_string()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_SUB)),
            CborValue::Text(subject.to_string()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_AUD)),
            CborValue::Text(VHSM_AUDIENCE.to_string()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_EXP)),
            CborValue::Integer(Integer::from(validity.exp)),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_NBF)),
            CborValue::Integer(Integer::from(validity.nbf)),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_IAT)),
            CborValue::Integer(Integer::from(validity.iat)),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_CTI)),
            CborValue::Bytes(cti.to_vec()),
        ),
        (
            CborValue::Integer(Integer::from(CLAIM_CNF)),
            cnf_wrapped,
        ),
    ]);

    let mut payload_bytes = Vec::new();
    ciborium::ser::into_writer(&claims, &mut payload_bytes)
        .map_err(|e| OffboardError::Other(format!("encode CWT payload: {e}")))?;

    let cose = CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(CoseAlg::ES256).build())
        .payload(payload_bytes)
        .create_signature(b"", |data| {
            let sig: Signature = signing_key.sign(data);
            sig.to_vec()
        })
        .build();
    cose.to_vec()
        .map_err(|e| OffboardError::Other(format!("encode COSE_Sign1: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::CoseSign1;
    use p256::ecdsa::{signature::Verifier as _, VerifyingKey};
    use p256::EncodedPoint;
    use rand::rngs::OsRng;

    fn sec1_split(sk: &SigningKey) -> (Vec<u8>, Vec<u8>) {
        let vk = sk.verifying_key();
        let p = vk.to_encoded_point(false);
        let bytes = p.as_bytes();
        (bytes[1..33].to_vec(), bytes[33..65].to_vec())
    }

    fn signer_pub(sk: &SigningKey) -> Vec<u8> {
        sk.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    #[test]
    fn minted_cwt_verifies_under_signer_pub() {
        // Smoke test: produce a CWT, parse it back, verify the
        // COSE_Sign1 signature using the signer's pubkey.
        let signer = SigningKey::random(&mut OsRng);
        let identity = SigningKey::random(&mut OsRng);
        let (x, y) = sec1_split(&identity);
        let cwt = mint_cwt(
            &signer,
            "vm9",
            "device-fleet-7",
            &x,
            &y,
            ValidityWindow::from_now(1_700_000_000, 86_400),
        )
        .unwrap();

        let cose = CoseSign1::from_slice(&cwt).expect("parse COSE_Sign1");
        let pk_bytes = signer_pub(&signer);
        let point = EncodedPoint::from_bytes(&pk_bytes).unwrap();
        let vk = VerifyingKey::from_encoded_point(&point).unwrap();
        cose.verify_signature(b"", |sig, data| {
            let sig = Signature::from_slice(sig).map_err(|_| ())?;
            vk.verify(data, &sig).map_err(|_| ())
        })
        .expect("CWT signature should verify under signer's pub");
    }

    #[test]
    fn minted_cwt_claims_are_recoverable() {
        let signer = SigningKey::random(&mut OsRng);
        let identity = SigningKey::random(&mut OsRng);
        let (x, y) = sec1_split(&identity);
        let cwt = mint_cwt(
            &signer,
            "vm9",
            "device-fleet-7",
            &x,
            &y,
            ValidityWindow {
                iat: 1_700_000_000,
                nbf: 1_700_000_000,
                exp: 1_700_086_400,
            },
        )
        .unwrap();

        let cose = CoseSign1::from_slice(&cwt).unwrap();
        let payload = cose.payload.as_deref().unwrap();
        let val: CborValue = ciborium::de::from_reader(payload).unwrap();
        let map = match val {
            CborValue::Map(m) => m,
            _ => panic!("payload not a map"),
        };

        // sub == "vm9"
        let sub = read_text(&map, CLAIM_SUB);
        assert_eq!(sub.as_deref(), Some("vm9"));
        // aud == VHSM_AUDIENCE
        let aud = read_text(&map, CLAIM_AUD);
        assert_eq!(aud.as_deref(), Some(VHSM_AUDIENCE));
        // iss == "device-fleet-7"
        let iss = read_text(&map, CLAIM_ISS);
        assert_eq!(iss.as_deref(), Some("device-fleet-7"));
        // exp == 1_700_086_400
        let exp = read_u64(&map, CLAIM_EXP);
        assert_eq!(exp, Some(1_700_086_400));
    }

    #[test]
    fn rejects_wrong_length_pubkey_coords() {
        let signer = SigningKey::random(&mut OsRng);
        let err = mint_cwt(
            &signer,
            "vm9",
            "device-test",
            &[0u8; 31],  // wrong length
            &[0u8; 32],
            ValidityWindow::from_now(0, 1),
        )
        .unwrap_err();
        let s = format!("{err:?}");
        assert!(s.contains("cnf pubkey"), "got: {s}");
    }

    #[test]
    fn cti_is_unique_across_two_mints() {
        // Same inputs → still different CWTs because the random cti
        // claim diverges. Catches regressions that zero-fill cti.
        let signer = SigningKey::random(&mut OsRng);
        let identity = SigningKey::random(&mut OsRng);
        let (x, y) = sec1_split(&identity);
        let v = ValidityWindow::from_now(1_700_000_000, 86_400);
        let a = mint_cwt(&signer, "vm9", "device-test", &x, &y, v).unwrap();
        let b = mint_cwt(&signer, "vm9", "device-test", &x, &y, v).unwrap();
        assert_ne!(a, b);
    }

    fn read_text(map: &[(CborValue, CborValue)], key: i64) -> Option<String> {
        for (k, v) in map {
            if let CborValue::Integer(i) = k {
                let ki: i128 = (*i).into();
                if ki == key as i128 {
                    if let CborValue::Text(s) = v {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    fn read_u64(map: &[(CborValue, CborValue)], key: i64) -> Option<u64> {
        for (k, v) in map {
            if let CborValue::Integer(i) = k {
                let ki: i128 = (*i).into();
                if ki == key as i128 {
                    if let CborValue::Integer(n) = v {
                        let ni: i128 = (*n).into();
                        if (0..=u64::MAX as i128).contains(&ni) {
                            return Some(ni as u64);
                        }
                    }
                }
            }
        }
        None
    }
}
