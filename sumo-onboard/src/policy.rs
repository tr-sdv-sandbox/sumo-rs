//! Persistent update policy (rollback protection).

use crate::error::Sum2Error;
use crate::manifest::Manifest;
use crate::platform::StorageOps;
use crate::validator::Validator;

/// Load persisted policy state into a validator.
///
/// Reads the minimum sequence number and reject-before timestamp from storage.
/// Missing keys are silently ignored (fresh device has no policy yet).
pub fn policy_load(validator: &mut Validator, storage: &dyn StorageOps) -> Result<(), Sum2Error> {
    if let Ok(seq) = storage.read_u64("sum2_seq") {
        validator.set_min_sequence(seq);
    }
    if let Ok(ts) = storage.read_i64("sum2_reject_before") {
        validator.set_reject_before(ts);
    }
    Ok(())
}

/// Save policy state (sequence number) after a successful update.
pub fn policy_save(manifest: &Manifest, storage: &dyn StorageOps) -> Result<(), Sum2Error> {
    storage.write_u64("sum2_seq", manifest.sequence_number())
}
