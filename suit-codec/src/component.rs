//! SUIT component identifiers and dependency info.

use std::vec::Vec;

/// A SUIT component identifier (array of bstr segments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentIdentifier {
    pub segments: Vec<Vec<u8>>,
}

/// Dependency metadata within a SUIT manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyInfo {
    pub index: usize,
    pub prefix: Option<ComponentIdentifier>,
}
