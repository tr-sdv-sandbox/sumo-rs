//! Encryption recipients.

use crate::cose_key::CoseKey;

/// A recipient for firmware encryption (device public key + identifier).
pub struct Recipient {
    pub public_key: CoseKey,
    pub kid: Vec<u8>,
}
