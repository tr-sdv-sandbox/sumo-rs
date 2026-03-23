//! SUIT text metadata.

use std::collections::BTreeMap;
use std::string::String;

/// Text metadata for a specific component.
#[derive(Debug, Clone, Default)]
pub struct TextComponent {
    pub vendor_name: Option<String>,
    pub model_name: Option<String>,
    pub vendor_domain: Option<String>,
    pub model_info: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
}

/// SUIT text section.
#[derive(Debug, Clone, Default)]
pub struct SuitText {
    pub description: Option<String>,
    pub components: BTreeMap<usize, TextComponent>,
}
