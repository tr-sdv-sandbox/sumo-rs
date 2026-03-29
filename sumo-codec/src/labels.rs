//! SUIT CBOR integer map key constants (RFC 9124).

// SUIT_Envelope keys
pub const SUIT_AUTHENTICATION_WRAPPER: i64 = 2;
pub const SUIT_MANIFEST: i64 = 3;

// SUIT_Manifest keys
pub const SUIT_MANIFEST_VERSION: i64 = 1;
pub const SUIT_MANIFEST_SEQUENCE_NUMBER: i64 = 2;
pub const SUIT_COMMON: i64 = 3;
pub const SUIT_PAYLOAD_FETCH: i64 = 16;
pub const SUIT_INSTALL: i64 = 20;
pub const SUIT_VALIDATE: i64 = 7;
pub const SUIT_INVOKE: i64 = 9;
pub const SUIT_DEPENDENCY_RESOLUTION: i64 = 15;
pub const SUIT_TEXT: i64 = 23;

// SUIT_Common keys
pub const SUIT_DEPENDENCIES: i64 = 1;
pub const SUIT_COMPONENTS: i64 = 2;
pub const SUIT_SHARED_SEQUENCE: i64 = 4;

// SUIT_Dependency keys
pub const SUIT_DEPENDENCY_PREFIX: i64 = 1;

// SUIT parameters
pub const SUIT_PARAMETER_VENDOR_IDENTIFIER: i64 = 1;
pub const SUIT_PARAMETER_CLASS_IDENTIFIER: i64 = 2;
pub const SUIT_PARAMETER_IMAGE_DIGEST: i64 = 3;
pub const SUIT_PARAMETER_IMAGE_SIZE: i64 = 14;
pub const SUIT_PARAMETER_URI: i64 = 21;
pub const SUIT_PARAMETER_ENCRYPTION_INFO: i64 = 19;
pub const SUIT_PARAMETER_VERSION: i64 = 26;
pub const SUIT_PARAMETER_DEVICE_IDENTIFIER: i64 = 24;

// Custom parameters (private use range, negative integers)
pub const SUIT_PARAMETER_SECURITY_VERSION: i64 = -257;

// SUIT directives
pub const SUIT_DIRECTIVE_SET_COMPONENT_INDEX: i64 = 12;
pub const SUIT_DIRECTIVE_SET_PARAMETERS: i64 = 19;
pub const SUIT_DIRECTIVE_OVERRIDE_PARAMETERS: i64 = 20;
pub const SUIT_DIRECTIVE_FETCH: i64 = 21;
pub const SUIT_DIRECTIVE_INVOKE: i64 = 23;
pub const SUIT_DIRECTIVE_PROCESS_DEPENDENCY: i64 = 11;
pub const SUIT_DIRECTIVE_SWAP: i64 = 31;

// SUIT conditions
pub const SUIT_CONDITION_VENDOR_IDENTIFIER: i64 = 1;
pub const SUIT_CONDITION_CLASS_IDENTIFIER: i64 = 2;
pub const SUIT_CONDITION_DEVICE_IDENTIFIER: i64 = 24;
pub const SUIT_CONDITION_IMAGE_MATCH: i64 = 3;
pub const SUIT_CONDITION_DEPENDENCY_INTEGRITY: i64 = 7;

// Digest algorithms
pub const SUIT_DIGEST_SHA256: i64 = -16;
pub const SUIT_DIGEST_SHA384: i64 = -43;
pub const SUIT_DIGEST_SHA512: i64 = -44;

// SUIT text keys
pub const SUIT_TEXT_MANIFEST_DESCRIPTION: i64 = 1;
pub const SUIT_TEXT_VENDOR_NAME: i64 = 1;
pub const SUIT_TEXT_MODEL_NAME: i64 = 2;
pub const SUIT_TEXT_VENDOR_DOMAIN: i64 = 3;
pub const SUIT_TEXT_MODEL_INFO: i64 = 4;
pub const SUIT_TEXT_COMPONENT_DESCRIPTION: i64 = 5;
pub const SUIT_TEXT_COMPONENT_VERSION: i64 = 6;
