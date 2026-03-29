//! SUIT Command Sequence Processor
//!
//! Implements the SUIT manifest abstract machine (RFC 9124 Section 6.4).
//! Walks command sequences in order, dispatches directives to PlatformOps,
//! evaluates conditions, and maintains per-component parameter state.
//!
//! # Execution Order
//!
//! 1. `shared_sequence` — sets parameters, checks device identity
//! 2. `dependency_resolution` — fetches L2 manifests (campaigns)
//! 3. `payload_fetch` — downloads firmware payloads
//! 4. `install` — writes firmware to storage (copy, write, swap)
//! 5. `validate` — verifies hashes after installation
//! 6. `invoke` — boots/executes updated components
//!
//! Each sequence is optional. Absent sequences are skipped.

mod processor;

pub use processor::{SuitProcessor, ProcessorConfig};
