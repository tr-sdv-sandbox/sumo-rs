//! Device identity (vendor, class, device UUIDs).

use suit_codec::Uuid;

/// Device identity used for manifest condition checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId {
    pub vendor_id: Uuid,
    pub class_id: Uuid,
    pub device_id: Uuid,
}
