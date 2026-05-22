//! Off-box helpers for vHSM v3 bootstrap-token provisioning.
//!
//! A bootstrap token is a single-use credential that lets a freshly-
//! flashed guest exchange a one-time secret for a long-lived CWT cert
//! via the vhsm-ssd ENROLL handshake (see `vhsm/protocol.md` §11.4).
//!
//! The operator (or fleet provisioning system) calls these helpers
//! when adding a new guest:
//!
//!   1. [`generate_token`] returns 32 random bytes. Write the raw
//!      bytes into the guest's firmware bank at
//!      `<bank>/vhsm-bootstrap.token`. The guest reads them on first
//!      boot, sends them in ENROLL, then deletes the file.
//!
//!   2. [`token_sha256_hex`] returns the lower-hex SHA-256 of the
//!      raw token. Record this in the daemon's bootstrap state
//!      (`<keystore>/bootstrap.yaml`) under the guest's vm_id. The
//!      daemon never stores the raw token — only its hash.
//!
//!   3. [`bootstrap_yaml_fragment`] formats a single-vm entry that
//!      can be merged into `bootstrap.yaml`. For one-shot CLI
//!      provisioning the helper emits the same shape that the
//!      daemon's `BootstrapState` reader expects.

use rand::RngCore as _;
use sha2::{Digest, Sha256};

/// Length of a bootstrap token in bytes. Sized to match the daemon
/// side's expected raw-token range (1..=255; we ship 32).
pub const TOKEN_LEN: usize = 32;

/// Generate a fresh bootstrap token via the OS CSPRNG. 32 random
/// bytes. Output is uniformly random; do not log it or copy it
/// through the network.
pub fn generate_token() -> [u8; TOKEN_LEN] {
    let mut t = [0u8; TOKEN_LEN];
    rand::thread_rng().fill_bytes(&mut t);
    t
}

/// Lower-hex SHA-256 of a raw bootstrap token (64 chars).
///
/// This is the exact format the daemon writes into its
/// `bootstrap.yaml`. Use [`bootstrap_yaml_fragment`] to format a
/// complete YAML entry.
pub fn token_sha256_hex(raw_token: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(raw_token);
    let digest = h.finalize();
    hex_lower(&digest)
}

/// Build a YAML fragment for a single fresh (un-consumed) bootstrap
/// entry. Indentation is 2-space, vm_id is quoted to defend against
/// names that happen to look like YAML keywords.
///
/// Example output:
/// ```yaml
///   "vm2":
///     sha256: "a3f1...0c"
///     consumed: false
/// ```
///
/// Operators merge this into the `tokens:` map of an existing
/// `bootstrap.yaml`. The daemon's `BootstrapState::load` reads any
/// file with the same shape produced by its own `save()`.
pub fn bootstrap_yaml_fragment(vm_id: &str, sha256_hex: &str) -> String {
    format!(
        "  \"{}\":\n    sha256: \"{}\"\n    consumed: false\n",
        yaml_escape(vm_id),
        sha256_hex,
    )
}

/// Build a full standalone `bootstrap.yaml` document carrying a
/// single fresh entry. Useful for first-time provisioning where the
/// file doesn't exist yet.
pub fn bootstrap_yaml_document(vm_id: &str, sha256_hex: &str) -> String {
    format!(
        "tokens:\n{}",
        bootstrap_yaml_fragment(vm_id, sha256_hex),
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Minimal YAML string escape — handles quote / backslash. Bootstrap
/// vm_ids are short identifiers (matching the daemon's principal
/// vocabulary), so we don't need full YAML escaping.
fn yaml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_token_is_correct_length_and_random() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), TOKEN_LEN);
        assert_eq!(b.len(), TOKEN_LEN);
        // Two fresh tokens collide with probability 2^-256 → never
        // in any realistic test run.
        assert_ne!(a, b);
    }

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hex = token_sha256_hex(b"");
        assert_eq!(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn sha256_of_token_is_lower_hex_64_chars() {
        let t = generate_token();
        let hex = token_sha256_hex(&t);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn yaml_fragment_round_trips_through_serde_yaml() {
        // The fragment we emit must be a valid YAML subtree the
        // daemon can load. Synthesise a full document, parse, and
        // confirm the fields are recovered.
        let frag = bootstrap_yaml_fragment("vm9", "abc123");
        let doc = format!("tokens:\n{frag}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap();
        let entry = &parsed["tokens"]["vm9"];
        assert_eq!(entry["sha256"], "abc123");
        assert_eq!(entry["consumed"], false);
    }

    #[test]
    fn yaml_document_is_self_contained() {
        let doc = bootstrap_yaml_document("vm-test", "deadbeef");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap();
        assert_eq!(parsed["tokens"]["vm-test"]["sha256"], "deadbeef");
        assert_eq!(parsed["tokens"]["vm-test"]["consumed"], false);
    }

    #[test]
    fn yaml_escapes_quote_and_backslash_in_vm_id() {
        // vm_ids should never contain these in practice, but the
        // escape function defends against operator typo / paste.
        let frag = bootstrap_yaml_fragment("vm\"\\test", "00");
        // The output should round-trip through serde_yaml.
        let doc = format!("tokens:\n{frag}");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&doc).unwrap();
        // After parsing, the key recovers to its un-escaped form.
        let map = parsed["tokens"].as_mapping().unwrap();
        let keys: Vec<&str> = map.keys().filter_map(|k| k.as_str()).collect();
        assert_eq!(keys, vec!["vm\"\\test"]);
    }

    #[test]
    fn token_and_hash_consistent() {
        // The hash recorded server-side must match a fresh hash of
        // the raw token a guest will replay. End-to-end consistency
        // check.
        let t = generate_token();
        let h1 = token_sha256_hex(&t);
        let h2 = token_sha256_hex(&t);
        assert_eq!(h1, h2);
    }
}
