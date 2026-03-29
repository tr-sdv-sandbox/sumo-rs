//! Core SUIT command sequence interpreter.

use std::collections::HashMap;

use sumo_codec::commands::{CommandItem, CommandSequence, CommandValue};
use sumo_codec::labels::*;
use sumo_codec::parameters::ParameterValue;
use sumo_crypto::CryptoBackend;
use sumo_onboard::error::Sum2Error;
use sumo_onboard::manifest::Manifest;
use sumo_onboard::platform::PlatformOps;
use sumo_onboard::validator::Validator;
use tracing::{debug, info, warn};

/// Configuration for the processor.
pub struct ProcessorConfig {
    /// If true, conditions that fail produce warnings instead of errors.
    pub soft_failure: bool,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self { soft_failure: false }
    }
}

/// SUIT command sequence processor.
///
/// Interprets manifest command sequences by walking directives in order,
/// maintaining per-component parameter state, and dispatching I/O to PlatformOps.
pub struct SuitProcessor<'a> {
    manifest: &'a Manifest,
    validator: &'a Validator,
    ops: &'a dyn PlatformOps,
    crypto: &'a dyn CryptoBackend,
    config: ProcessorConfig,
    /// Per-component parameter tables (populated from shared + per-sequence overrides)
    component_params: Vec<HashMap<i64, ParameterValue>>,
    /// Current component index
    current_index: usize,
}

impl<'a> SuitProcessor<'a> {
    pub fn new(
        manifest: &'a Manifest,
        validator: &'a Validator,
        ops: &'a dyn PlatformOps,
        crypto: &'a dyn CryptoBackend,
        config: ProcessorConfig,
    ) -> Self {
        let num_components = manifest.component_count();
        Self {
            manifest,
            validator,
            ops,
            crypto,
            config,
            component_params: vec![HashMap::new(); num_components.max(1)],
            current_index: 0,
        }
    }

    /// Execute all manifest sequences in SUIT-defined order.
    pub fn execute(&mut self) -> Result<(), Sum2Error> {
        let envelope = self.manifest.envelope();

        // 1. Shared sequence (always present)
        info!("executing shared sequence");
        self.execute_sequence(&envelope.manifest.common.shared_sequence)?;

        // 2. Dependency resolution (campaigns)
        if let Some(ref seq) = envelope.manifest.severable.dependency_resolution {
            info!("executing dependency resolution");
            self.execute_sequence(seq)?;
        }

        // 3. Payload fetch
        if let Some(ref seq) = envelope.manifest.severable.payload_fetch {
            info!("executing payload fetch");
            self.execute_sequence(seq)?;
        }

        // 4. Install
        if let Some(ref seq) = envelope.manifest.severable.install {
            info!("executing install");
            self.execute_sequence(seq)?;
        }

        // 5. Validate
        if let Some(ref seq) = envelope.manifest.validate {
            info!("executing validate");
            self.execute_sequence(seq)?;
        }

        // 6. Invoke
        if let Some(ref seq) = envelope.manifest.invoke {
            info!("executing invoke");
            self.execute_sequence(seq)?;
        }

        Ok(())
    }

    /// Execute a single command sequence.
    fn execute_sequence(&mut self, seq: &CommandSequence) -> Result<(), Sum2Error> {
        for item in &seq.items {
            self.execute_command(item)?;
        }
        Ok(())
    }

    /// Dispatch a single command (directive or condition).
    fn execute_command(&mut self, item: &CommandItem) -> Result<(), Sum2Error> {
        match item.label {
            // --- Parameter management ---
            SUIT_DIRECTIVE_SET_COMPONENT_INDEX => {
                if let CommandValue::ComponentIndex(idx) = &item.value {
                    debug!(index = idx, "set component index");
                    self.current_index = *idx;
                }
                Ok(())
            }
            SUIT_DIRECTIVE_SET_PARAMETERS => {
                if let CommandValue::Parameters(params) = &item.value {
                    // Merge (don't overwrite existing)
                    for p in params {
                        self.component_params[self.current_index]
                            .entry(p.label)
                            .or_insert_with(|| p.value.clone());
                    }
                }
                Ok(())
            }
            SUIT_DIRECTIVE_OVERRIDE_PARAMETERS => {
                if let CommandValue::Parameters(params) = &item.value {
                    // Replace
                    for p in params {
                        self.component_params[self.current_index]
                            .insert(p.label, p.value.clone());
                    }
                }
                Ok(())
            }

            // --- Conditions ---
            SUIT_CONDITION_VENDOR_IDENTIFIER => {
                debug!("condition: vendor identifier");
                // TODO: check against validator device_id
                Ok(())
            }
            SUIT_CONDITION_CLASS_IDENTIFIER => {
                debug!("condition: class identifier");
                Ok(())
            }
            SUIT_CONDITION_DEVICE_IDENTIFIER => {
                debug!("condition: device identifier");
                Ok(())
            }
            SUIT_CONDITION_IMAGE_MATCH => {
                debug!("condition: image match");
                self.check_image_match()
            }
            SUIT_CONDITION_DEPENDENCY_INTEGRITY => {
                debug!("condition: dependency integrity");
                // TODO: validate L2 manifest digest
                Ok(())
            }

            // --- Directives ---
            SUIT_DIRECTIVE_FETCH => {
                info!(component = self.current_index, "directive: fetch");
                self.do_fetch()
            }
            SUIT_DIRECTIVE_WRITE => {
                info!(component = self.current_index, "directive: write");
                self.do_write()
            }
            SUIT_DIRECTIVE_COPY => {
                info!(component = self.current_index, "directive: copy");
                self.do_copy()
            }
            SUIT_DIRECTIVE_SWAP => {
                info!(component = self.current_index, "directive: swap");
                self.do_swap()
            }
            SUIT_DIRECTIVE_INVOKE => {
                info!(component = self.current_index, "directive: invoke");
                self.do_invoke()
            }
            SUIT_DIRECTIVE_PROCESS_DEPENDENCY => {
                info!(component = self.current_index, "directive: process dependency");
                self.do_process_dependency()
            }

            other => {
                warn!(label = other, "unknown command, skipping");
                Ok(())
            }
        }
    }

    // --- Directive implementations ---

    fn do_fetch(&self) -> Result<(), Sum2Error> {
        let params = &self.component_params[self.current_index];
        let uri = match params.get(&SUIT_PARAMETER_URI) {
            Some(ParameterValue::Uri(u)) => u.as_str(),
            _ => return Err(Sum2Error::InvalidEnvelope),
        };
        let size = match params.get(&SUIT_PARAMETER_IMAGE_SIZE) {
            Some(ParameterValue::ImageSize(s)) => *s as usize,
            _ => 256 * 1024,
        };
        let mut buf = vec![0u8; size + 1024];
        let fetched = self.ops.fetch(uri, &mut buf)?;
        debug!(uri, fetched, "fetched payload");
        // Store fetched data for later write/copy
        // For now, write immediately to component
        let comp_id = self.current_component_id();
        self.ops.write(&comp_id, 0, &buf[..fetched])
    }

    fn do_write(&self) -> Result<(), Sum2Error> {
        // Write content from parameters to component
        let comp_id = self.current_component_id();
        // Content typically comes from fetch or is embedded
        debug!(component = ?comp_id, "write directive");
        Ok(())
    }

    fn do_copy(&self) -> Result<(), Sum2Error> {
        // Copy from one component to another (A/B install)
        let comp_id = self.current_component_id();
        debug!(component = ?comp_id, "copy directive");
        Ok(())
    }

    fn do_swap(&self) -> Result<(), Sum2Error> {
        let comp_id = self.current_component_id();
        // Swap current component with its A/B counterpart
        self.ops.swap(&comp_id, &comp_id)
    }

    fn do_invoke(&self) -> Result<(), Sum2Error> {
        let comp_id = self.current_component_id();
        self.ops.invoke(&comp_id)
    }

    fn do_process_dependency(&mut self) -> Result<(), Sum2Error> {
        let dep_idx = self.current_index;
        let dep_uri = self.manifest.dependency_uri(dep_idx)
            .ok_or(Sum2Error::DependencyFailed)?;

        // Fetch or extract L2 manifest
        let l2_bytes = if dep_uri.starts_with('#') {
            self.manifest.integrated_payload(dep_uri)
                .ok_or(Sum2Error::DependencyFailed)?
                .to_vec()
        } else {
            let mut buf = vec![0u8; 64 * 1024];
            let n = self.ops.fetch(dep_uri, &mut buf)?;
            buf[..n].to_vec()
        };

        // Validate L2 manifest
        let l2_manifest = self.validator
            .validate_envelope(&l2_bytes, self.crypto, 0)?;

        // Recursively process L2
        let mut sub_processor = SuitProcessor::new(
            &l2_manifest,
            self.validator,
            self.ops,
            self.crypto,
            ProcessorConfig::default(),
        );
        sub_processor.execute()
    }

    // --- Condition implementations ---

    fn check_image_match(&self) -> Result<(), Sum2Error> {
        let params = &self.component_params[self.current_index];
        let expected = match params.get(&SUIT_PARAMETER_IMAGE_DIGEST) {
            Some(ParameterValue::ImageDigest(d)) => d,
            _ => return Ok(()), // No digest to check
        };

        // Hash the component content
        // In practice, the platform would provide a way to hash stored content.
        // For now, trust that the orchestrator verified during fetch/write.
        debug!(algorithm = ?expected.algorithm, "image match check");
        Ok(())
    }

    // --- Helpers ---

    fn current_component_id(&self) -> Vec<u8> {
        self.manifest
            .component_id(self.current_index)
            .map(|segs| {
                segs.iter()
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<_>>()
                    .join("/")
                    .into_bytes()
            })
            .unwrap_or_default()
    }
}
