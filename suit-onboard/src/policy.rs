//! Persistent update policy (rollback protection).

use crate::error::Sum2Error;
use crate::manifest::Manifest;
use crate::platform::StorageOps;
use crate::validator::Validator;

/// Load persisted policy state into a validator.
pub fn policy_load(_validator: &mut Validator, _storage: &dyn StorageOps) -> Result<(), Sum2Error> {
    // TODO: Phase 5
    Ok(())
}

/// Save policy state (sequence number) after a successful update.
pub fn policy_save(_manifest: &Manifest, _storage: &dyn StorageOps) -> Result<(), Sum2Error> {
    // TODO: Phase 5
    Ok(())
}
