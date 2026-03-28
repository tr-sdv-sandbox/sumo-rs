//! SUIT command sequences and items.

use std::vec::Vec;

use crate::parameters::SuitParameter;

/// A sequence of SUIT commands.
#[derive(Debug, Clone, Default)]
pub struct CommandSequence {
    pub items: Vec<CommandItem>,
}

/// A single command in a sequence.
#[derive(Debug, Clone)]
pub struct CommandItem {
    pub label: i64,
    pub value: CommandValue,
}

/// The value associated with a command.
#[derive(Debug, Clone)]
pub enum CommandValue {
    /// Parameters for set-parameters / override-parameters.
    Parameters(Vec<SuitParameter>),
    /// Component index for set-component-index.
    ComponentIndex(usize),
    /// Reporting policy (uint) for conditions and directives.
    ReportingPolicy(u64),
}
