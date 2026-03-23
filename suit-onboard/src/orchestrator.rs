//! Two-level manifest orchestration (campaign → image).

use crate::error::Sum2Error;
use crate::manifest::Manifest;
use crate::platform::PlatformOps;
use crate::validator::Validator;

/// Process a single-image manifest: fetch, decrypt, decompress, verify, write.
pub fn process_image(
    _validator: &Validator,
    _manifest: &Manifest,
    _ops: &dyn PlatformOps,
) -> Result<(), Sum2Error> {
    // TODO: Phase 5
    Err(Sum2Error::Unsupported)
}

/// Process a campaign manifest: iterate dependencies, fetch/validate L2 manifests,
/// then process each image.
pub fn process_campaign(
    _validator: &Validator,
    _manifest: &Manifest,
    _ops: &dyn PlatformOps,
) -> Result<(), Sum2Error> {
    // TODO: Phase 5
    Err(Sum2Error::Unsupported)
}
