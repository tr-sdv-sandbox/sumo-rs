//! SUIT manifest and common structures.

use std::vec::Vec;

use crate::commands::CommandSequence;
use crate::component::{ComponentIdentifier, DependencyInfo};
use crate::text::SuitText;

/// The SUIT_Common structure.
#[derive(Debug, Clone, Default)]
pub struct SuitCommon {
    pub components: Vec<ComponentIdentifier>,
    pub dependencies: Vec<DependencyInfo>,
    pub shared_sequence: CommandSequence,
}

/// Severable manifest members.
#[derive(Debug, Clone, Default)]
pub struct SeverableMembers {
    pub payload_fetch: Option<CommandSequence>,
    pub install: Option<CommandSequence>,
    pub dependency_resolution: Option<CommandSequence>,
    pub text: Option<SuitText>,
}

/// The SUIT_Manifest structure.
#[derive(Debug, Clone)]
pub struct SuitManifest {
    pub manifest_version: u32,
    pub sequence_number: u64,
    pub common: SuitCommon,
    pub validate: Option<CommandSequence>,
    pub invoke: Option<CommandSequence>,
    pub severable: SeverableMembers,
}

impl Default for SuitManifest {
    fn default() -> Self {
        Self {
            manifest_version: 1,
            sequence_number: 0,
            common: SuitCommon::default(),
            validate: None,
            invoke: None,
            severable: SeverableMembers::default(),
        }
    }
}
