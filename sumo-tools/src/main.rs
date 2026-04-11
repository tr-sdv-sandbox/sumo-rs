//! sumo-tool: CLI for SUIT firmware update manifest operations.

mod manifest;

use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sumo_crypto::{CryptoBackend, RustCryptoBackend};
use sumo_offboard::cose_key::CoseKey;
use sumo_offboard::encryptor;
use sumo_offboard::image_builder::ImageManifestBuilder;
use sumo_offboard::campaign_builder::CampaignBuilder;
use sumo_offboard::keygen;
use sumo_offboard::recipient::Recipient;
use sumo_codec::types::Uuid;

#[derive(Parser)]
#[command(name = "sumo-tool", about = "SUIT manifest and key management tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a signing or device key pair.
    Keygen {
        /// Algorithm: es256 or eddsa
        #[arg(short, long, default_value = "es256")]
        algorithm: String,

        /// Output path for the private key (COSE_Key CBOR)
        #[arg(short, long)]
        output: PathBuf,

        /// Also write the public key to this path
        #[arg(short, long)]
        public: Option<PathBuf>,

        /// Generate a device key (ECDH) instead of a signing key
        #[arg(long)]
        device: bool,
    },

    /// Build an L2 image manifest.
    ///
    /// Two modes:
    ///   1. With --firmware: reads file, optionally compresses+encrypts, computes digest
    ///   2. Without --firmware: reference build using --payload-digest + --payload-size
    ///
    /// Alternatively, use --manifest to provide all parameters via a YAML file.
    Build {
        /// YAML manifest descriptor file (use "-" for stdin).
        /// When provided, other Build flags are ignored.
        #[arg(short, long)]
        manifest: Option<String>,

        /// Signing key file (COSE_Key CBOR)
        #[arg(short = 'k', long)]
        signing_key: Option<PathBuf>,

        /// Firmware payload file (omit for reference builds with --payload-digest)
        #[arg(short, long)]
        firmware: Option<PathBuf>,

        /// Output envelope file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Component ID segments (e.g., "ecu-a,firmware")
        #[arg(short, long)]
        component: Option<String>,

        /// Sequence number
        #[arg(short, long, default_value = "1")]
        seq: u64,

        /// Vendor UUID (hex, 16 bytes)
        #[arg(long)]
        vendor: Option<String>,

        /// Class UUID (hex, 16 bytes)
        #[arg(long)]
        class: Option<String>,

        /// Payload fetch URI
        #[arg(long)]
        uri: Option<String>,

        /// Encrypt with A128KW using these device key files (comma-separated)
        #[arg(long)]
        encrypt: Option<String>,

        /// Compress with zstd before encryption
        #[arg(long)]
        compress: bool,

        /// Write encrypted payload to this file (instead of embedding).
        /// Also writes {path}.enc-info with the encryption_info CBOR.
        #[arg(long)]
        payload_output: Option<PathBuf>,

        /// Security version (anti-rollback floor, separate from sequence number)
        #[arg(long)]
        security_version: Option<u64>,

        /// Human-readable version string (e.g., "1.2.0")
        #[arg(long)]
        version: Option<String>,

        /// Model name (e.g., "OS1-Linux")
        #[arg(long)]
        model_name: Option<String>,

        /// Description / spare part number
        #[arg(long)]
        description: Option<String>,

        /// SHA-256 digest of plaintext firmware (hex, for reference builds without --firmware)
        #[arg(long)]
        payload_digest: Option<String>,

        /// Size of plaintext firmware in bytes (for reference builds without --firmware)
        #[arg(long)]
        payload_size: Option<u64>,

        /// Path to encryption_info CBOR file (for reference builds, from a prior --payload-output)
        #[arg(long)]
        encryption_info: Option<PathBuf>,
    },

    /// Inspect a SUIT envelope.
    Inspect {
        /// SUIT envelope file
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Attach payload(s) to a reference manifest, creating an integrated envelope.
    ///
    /// Takes a small reference manifest and one or more separate payload files,
    /// and produces a new envelope with the payloads embedded.
    /// The manifest signature is preserved (it covers only the manifest, not payloads).
    ///
    /// For single payload: `-p payload.bin --key "#firmware"`
    /// For multiple: `-p payload.bin --key "#firmware" -p kernel.bin --key "#kernel"`
    Attach {
        /// Reference manifest file (SUIT envelope without integrated payload)
        #[arg(short, long)]
        manifest: PathBuf,

        /// Payload file(s) to embed (repeatable)
        #[arg(short, long)]
        payload: Vec<PathBuf>,

        /// Output envelope file (manifest + integrated payload)
        #[arg(short, long)]
        output: PathBuf,

        /// Payload key(s) in the envelope (repeatable, matches -p order)
        #[arg(long)]
        key: Vec<String>,
    },

    /// Build an L1 campaign manifest.
    Campaign {
        /// Signing key file (COSE_Key CBOR)
        #[arg(short = 'k', long)]
        signing_key: PathBuf,

        /// L2 manifest files to include as dependencies (comma-separated URI=file pairs)
        #[arg(short, long)]
        deps: String,

        /// Output envelope file
        #[arg(short, long)]
        output: PathBuf,

        /// Sequence number
        #[arg(short, long, default_value = "1")]
        seq: u64,

        /// Vendor UUID (hex, 16 bytes)
        #[arg(long)]
        vendor: Option<String>,

        /// Class UUID (hex, 16 bytes)
        #[arg(long)]
        class: Option<String>,
    },

    /// Re-wrap a CEK for a new device key (ECDH-ES+A128KW).
    ///
    /// Reads the plaintext CEK and original enc-info, wraps the CEK for a
    /// new device public key, and outputs a new enc-info file. The payload
    /// ciphertext is unchanged — only the manifest needs rebuilding.
    /// Re-wrap CEK(s) for a new device key (ECDH-ES+A128KW).
    ///
    /// Reads plaintext CEK(s) and original enc-info(s), wraps each CEK for
    /// a new device public key, and outputs new enc-info file(s).
    ///
    /// Single:   `--cek X.cek --enc-info X.enc-info -o X.new.enc-info`
    /// Multiple: `--cek K.cek --enc-info K.enc-info --cek R.cek --enc-info R.enc-info -o /tmp/out/`
    Rewrap {
        /// Path(s) to plaintext CEK file(s) (16 bytes each, repeatable)
        #[arg(long)]
        cek: Vec<PathBuf>,

        /// Path(s) to original encryption_info CBOR file(s) (repeatable, matches --cek order)
        #[arg(long)]
        enc_info: Vec<PathBuf>,

        /// Device public key file (COSE_Key CBOR, EC2 P-256)
        #[arg(long)]
        device_key: PathBuf,

        /// Output path. Single CEK: file path. Multiple CEKs: directory (files named from input).
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn parse_uuid(hex_str: &str) -> Result<Uuid, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid UUID hex: {e}"))?;
    if bytes.len() != 16 {
        return Err("UUID must be 16 bytes".into());
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(Uuid(arr))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Keygen {
            algorithm,
            output,
            public,
            device,
        } => {
            let alg = match algorithm.as_str() {
                "es256" => keygen::ES256,
                "eddsa" => keygen::EDDSA,
                _ => return Err(format!("unsupported algorithm: {algorithm}").into()),
            };

            let key = if device {
                keygen::generate_device_key(alg)?
            } else {
                keygen::generate_signing_key(alg)?
            };

            let private_bytes = keygen::serialize_key(&key, true)?;
            fs::write(&output, &private_bytes)?;
            eprintln!("Wrote private key to {}", output.display());

            if let Some(pub_path) = public {
                let pub_bytes = keygen::serialize_key(&key, false)?;
                fs::write(&pub_path, &pub_bytes)?;
                eprintln!("Wrote public key to {}", pub_path.display());
            }
        }

        Command::Build {
            manifest: Some(ref manifest_path),
            ..
        } => {
            // YAML-driven build path
            let yaml_str = if manifest_path == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                fs::read_to_string(manifest_path)?
            };
            let desc: manifest::ManifestDescriptor = serde_yaml::from_str(&yaml_str)
                .map_err(|e| format!("failed to parse manifest YAML: {e}"))?;

            // Stdin conflict: can't read both YAML and payload from stdin
            if manifest_path == "-" {
                if let Some(ref p) = desc.payload {
                    if p.file.as_deref() == Some("-") {
                        return Err("cannot read both manifest and payload from stdin; \
                            write the manifest to a file or use a named pipe".into());
                    }
                }
            }

            build_from_manifest(desc)?;
        }

        Command::Build {
            manifest: None,
            signing_key,
            firmware,
            output,
            component,
            seq,
            vendor,
            class,
            uri,
            encrypt,
            compress,
            payload_output,
            security_version,
            version,
            model_name,
            description,
            payload_digest: payload_digest_hex,
            payload_size,
            encryption_info: encryption_info_path,
        } => {
            // CLI-flags build path
            let signing_key = signing_key
                .ok_or("--signing-key is required (or use --manifest)")?;
            let output = output
                .ok_or("--output is required (or use --manifest)")?;
            let component = component
                .ok_or("--component is required (or use --manifest)")?;

            let key_bytes = fs::read(&signing_key)?;
            let key = CoseKey::from_cose_key_bytes(&key_bytes)?;
            let comp_id: Vec<String> = component.split(',').map(|s| s.to_string()).collect();

            // Two modes: firmware file (full build) or digest+size (reference build)
            let (digest, fw_size, final_payload, enc_info, cek) = if let Some(ref fw_path) = firmware {
                if payload_digest_hex.is_some() || payload_size.is_some() {
                    return Err("cannot use --firmware with --payload-digest/--payload-size".into());
                }

                let fw_data = fs::read(fw_path)?;
                let encrypt_paths: Vec<PathBuf> = encrypt
                    .as_deref()
                    .map(|s| s.split(',').map(|p| PathBuf::from(p.trim())).collect())
                    .unwrap_or_default();

                let (digest, fw_size, final_payload, enc_info, cek) =
                    process_payload(&fw_data, compress, &encrypt_paths)?;
                (digest, fw_size, Some(final_payload), enc_info, cek)
            } else {
                // Reference build mode — no firmware file
                let digest_hex = payload_digest_hex
                    .ok_or("--payload-digest required when --firmware is omitted")?;
                let size = payload_size
                    .ok_or("--payload-size required when --firmware is omitted")?;
                if compress || encrypt.is_some() {
                    return Err("--compress/--encrypt require --firmware".into());
                }

                let digest = parse_digest_hex(&digest_hex)?;

                // Load encryption_info from file if provided
                let enc_info = encryption_info_path
                    .map(|p| fs::read(&p))
                    .transpose()
                    .map_err(|e| format!("read --encryption-info: {e}"))?;

                (digest, size, None, enc_info, None)
            };

            let mut builder = ImageManifestBuilder::new()
                .component_id(comp_id)
                .sequence_number(seq)
                .payload_digest(&digest, fw_size);

            if let Some(v) = vendor {
                builder = builder.vendor_id(parse_uuid(&v)?);
            }
            if let Some(c) = class {
                builder = builder.class_id(parse_uuid(&c)?);
            }
            if let Some(u) = uri {
                builder = builder.payload_uri(u);
            }
            if let Some(ref ei) = enc_info {
                builder = builder.encryption_info(ei);
            }
            if let Some(sv) = security_version {
                builder = builder.security_version(sv);
            }
            if let Some(ref v) = version {
                builder = builder.text_version(v);
            }
            if let Some(ref mn) = model_name {
                builder = builder.text_model_name(mn);
            }
            if let Some(ref d) = description {
                builder = builder.text_description(d);
            }

            builder = builder.payload_uri("#firmware".to_string());

            if let Some(ref fp) = final_payload {
                if payload_output.is_none() {
                    builder = builder
                        .integrated_payload("#firmware".to_string(), fp.clone());
                }
            }

            let envelope = builder.build(&key)?;
            fs::write(&output, &envelope)?;
            eprintln!("Wrote manifest to {} ({} bytes)", output.display(), envelope.len());

            if let Some(po) = payload_output {
                if let Some(ref fp) = final_payload {
                    fs::write(&po, fp)?;
                    eprintln!("Wrote payload to {} ({} bytes)", po.display(), fp.len());

                    if let Some(ref ei) = enc_info {
                        let ei_path = PathBuf::from(format!("{}.enc-info", po.display()));
                        fs::write(&ei_path, ei)?;
                        eprintln!("Wrote encryption info to {} ({} bytes)", ei_path.display(), ei.len());
                    }
                    if let Some(ref cek_bytes) = cek {
                        let cek_path = PathBuf::from(format!("{}.cek", po.display()));
                        fs::write(&cek_path, cek_bytes)?;
                        eprintln!("Wrote CEK to {} (SENSITIVE)", cek_path.display());
                    }
                }
            }
        }

        Command::Inspect { input } => {
            let data = fs::read(&input)?;

            match sumo_codec::decode::decode_envelope(&data) {
                Ok(envelope) => {
                    let m = &envelope.manifest;
                    println!("SUIT Envelope: {}", input.display());
                    println!("  Manifest version: {}", m.manifest_version);
                    println!("  Sequence number:  {}", m.sequence_number);
                    println!("  Components:       {}", m.common.components.len());
                    println!("  Dependencies:     {}", m.common.dependencies.len());
                    println!("  Signatures:       {}", envelope.authentication.signatures.len());
                    println!("  Integrated payloads: {}", envelope.integrated_payloads.len());

                    for (i, comp) in m.common.components.iter().enumerate() {
                        let segs: Vec<String> = comp
                            .segments
                            .iter()
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect();
                        println!("  Component {i}: [{}]", segs.join(", "));
                    }

                    if m.common.dependencies.len() > 0 {
                        println!("  (Campaign manifest with {} dependencies)", m.common.dependencies.len());
                    }

                    // Digest info
                    let d = &envelope.authentication.digest;
                    println!("  Digest: {:?} {}", d.algorithm, hex::encode(&d.bytes));

                    if let Some(ref text) = m.severable.text {
                        if let Some(ref desc) = text.description {
                            println!("  Description: {desc}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to decode envelope: {e:?}");
                    std::process::exit(1);
                }
            }
        }

        Command::Attach {
            manifest,
            payload,
            output,
            key,
        } => {
            // Default key for backward compatibility
            let keys: Vec<String> = if key.is_empty() {
                payload.iter().map(|_| "#firmware".to_string()).collect()
            } else {
                key
            };

            if payload.len() != keys.len() {
                return Err(format!(
                    "mismatched -p and --key counts: {} payloads, {} keys",
                    payload.len(), keys.len()
                ).into());
            }

            let manifest_data = fs::read(&manifest)?;

            // Work at raw CBOR level to preserve the original signature.
            let value: ciborium::Value = ciborium::de::from_reader(manifest_data.as_slice())
                .map_err(|e| format!("failed to decode CBOR: {e}"))?;

            let entries = match value {
                ciborium::Value::Map(entries) => entries,
                _ => return Err("envelope is not a CBOR map".into()),
            };

            let mut new_entries = entries;
            for (p, k) in payload.iter().zip(keys.iter()) {
                let payload_data = fs::read(p)?;
                eprintln!("Attaching payload ({} bytes) as {:?}", payload_data.len(), k);
                new_entries.push((
                    ciborium::Value::Text(k.clone()),
                    ciborium::Value::Bytes(payload_data),
                ));
            }

            let new_map = ciborium::Value::Map(new_entries);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&new_map, &mut buf)
                .map_err(|e| format!("failed to encode CBOR: {e}"))?;

            fs::write(&output, &buf)?;
            eprintln!("Wrote integrated envelope to {} ({} bytes)", output.display(), buf.len());
        }

        Command::Campaign {
            signing_key,
            deps,
            output,
            seq,
            vendor,
            class,
        } => {
            let key_bytes = fs::read(&signing_key)?;
            let key = CoseKey::from_cose_key_bytes(&key_bytes)?;

            let mut builder = CampaignBuilder::new().sequence_number(seq);

            if let Some(v) = vendor {
                builder = builder.vendor_id(parse_uuid(&v)?);
            }
            if let Some(c) = class {
                builder = builder.class_id(parse_uuid(&c)?);
            }

            // Parse deps: "uri1=file1,uri2=file2" or "#key1=file1" for integrated
            for dep_spec in deps.split(',') {
                let dep_spec = dep_spec.trim();
                if let Some((uri, file_path)) = dep_spec.split_once('=') {
                    let l2_bytes = fs::read(file_path)?;
                    if uri.starts_with('#') {
                        builder = builder.add_integrated_image(uri[1..].to_string(), &l2_bytes);
                    } else {
                        builder = builder.add_image(uri.to_string(), &l2_bytes);
                    }
                } else {
                    return Err(format!("invalid dep spec: {dep_spec} (expected URI=file)").into());
                }
            }

            let envelope = builder.build(&key)?;
            fs::write(&output, &envelope)?;
            eprintln!(
                "Wrote campaign manifest to {} ({} bytes)",
                output.display(),
                envelope.len()
            );
        }

        Command::Rewrap {
            cek,
            enc_info,
            device_key,
            output,
        } => {
            if cek.len() != enc_info.len() {
                return Err(format!(
                    "mismatched --cek and --enc-info counts: {} vs {}",
                    cek.len(), enc_info.len()
                ).into());
            }
            if cek.is_empty() {
                return Err("at least one --cek + --enc-info pair required".into());
            }

            let dk_bytes = fs::read(&device_key)?;
            let dk = CoseKey::from_cose_key_bytes(&dk_bytes)?;
            let recipient = Recipient {
                public_key: dk,
                kid: device_key.to_string_lossy().as_bytes().to_vec(),
            };

            for (i, (cek_path, ei_path)) in cek.iter().zip(enc_info.iter()).enumerate() {
                let cek_bytes = fs::read(cek_path)?;
                if cek_bytes.len() != 16 {
                    return Err(format!("CEK {} must be 16 bytes, got {}", cek_path.display(), cek_bytes.len()).into());
                }
                let mut cek_arr = [0u8; 16];
                cek_arr.copy_from_slice(&cek_bytes);

                let enc_info_bytes = fs::read(ei_path)?;
                let iv = encryptor::extract_iv_from_enc_info(&enc_info_bytes)?;

                let new_enc_info = encryptor::rewrap_cek_ecdh(&cek_arr, &iv, &recipient)?;

                // Single CEK: output is a file. Multiple: output is a directory.
                let out_path = if cek.len() == 1 {
                    output.clone()
                } else {
                    let name = ei_path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| format!("enc-info-{i}"));
                    fs::create_dir_all(&output)?;
                    output.join(name)
                };

                fs::write(&out_path, &new_enc_info)?;
                eprintln!(
                    "Wrote re-wrapped encryption info to {} ({} bytes)",
                    out_path.display(),
                    new_enc_info.len()
                );
            }
        }
    }

    Ok(())
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Parse a hex SHA-256 digest string into a 32-byte array.
fn parse_digest_hex(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format!("invalid digest hex: {e}"))?;
    if bytes.len() != 32 {
        return Err("digest must be 64 hex chars (32 bytes SHA-256)".into());
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

/// Compress, encrypt, and compute digest for a firmware payload.
///
/// Returns `(sha256_digest, plaintext_size, processed_payload, encryption_info)`.
fn process_payload(
    fw_data: &[u8],
    compress: bool,
    encrypt_key_paths: &[PathBuf],
) -> Result<([u8; 32], u64, Vec<u8>, Option<Vec<u8>>, Option<[u8; 16]>), Box<dyn std::error::Error>> {
    let crypto = RustCryptoBackend::new();

    // Optionally compress
    let payload = if compress {
        eprintln!("Compressing payload ({} bytes)...", fw_data.len());
        encryptor::compress_firmware(fw_data, 3)?
    } else {
        fw_data.to_vec()
    };

    // Optionally encrypt
    let (final_payload, enc_info, cek) = if !encrypt_key_paths.is_empty() {
        let recipients: Vec<Recipient> = encrypt_key_paths
            .iter()
            .map(|path| {
                let kb = fs::read(path)
                    .unwrap_or_else(|_| panic!("cannot read key file: {}", path.display()));
                let dk = CoseKey::from_cose_key_bytes(&kb)
                    .unwrap_or_else(|_| panic!("invalid key file: {}", path.display()));
                Recipient {
                    public_key: dk,
                    kid: path.to_string_lossy().as_bytes().to_vec(),
                }
            })
            .collect();

        let is_ecdh = recipients.first().map_or(false, |r| r.public_key.is_ec2());

        let encrypted = if is_ecdh {
            let sender_key = keygen::generate_device_key(keygen::ES256)?;
            let pub_recipients: Vec<Recipient> = recipients
                .into_iter()
                .map(|r| Recipient {
                    public_key: CoseKey::from_cose_key_bytes(&r.public_key.public_key_bytes()).unwrap(),
                    kid: r.kid,
                })
                .collect();
            eprintln!("Using ECDH-ES+A128KW encryption");
            encryptor::encrypt_firmware_ecdh(&payload, &sender_key, &pub_recipients)?
        } else {
            eprintln!("Using A128KW encryption");
            encryptor::encrypt_firmware(&payload, &recipients)?
        };

        eprintln!("Encrypted payload: {} bytes", encrypted.ciphertext.len());
        (encrypted.ciphertext, Some(encrypted.encryption_info), Some(encrypted.cek))
    } else {
        (payload, None, None)
    };

    let digest = crypto.sha256(fw_data);
    Ok((digest, fw_data.len() as u64, final_payload, enc_info, cek))
}

/// Build a SUIT manifest from a YAML descriptor.
fn build_from_manifest(desc: manifest::ManifestDescriptor) -> Result<(), Box<dyn std::error::Error>> {
    if desc.is_multi_component() {
        return build_multi_component_manifest(desc);
    }

    let key_bytes = fs::read(&desc.signing_key)?;
    let key = CoseKey::from_cose_key_bytes(&key_bytes)?;
    let comp_id = desc.component_id
        .ok_or("component_id required for single-component manifest")?
        .to_vec();

    // Determine payload mode
    let (digest, fw_size, final_payload, enc_info, cek) = match desc.payload {
        None => {
            // CRL / policy-only manifest — no payload
            let mut builder = ImageManifestBuilder::new()
                .component_id(comp_id)
                .sequence_number(desc.sequence_number);

            if let Some(sv) = desc.security_version {
                builder = builder.security_version(sv);
            }
            builder = apply_metadata(builder, desc.metadata.as_ref());

            let envelope = builder.build(&key)?;
            fs::write(&desc.output.manifest, &envelope)?;
            eprintln!(
                "Wrote manifest to {} ({} bytes)",
                desc.output.manifest.display(),
                envelope.len()
            );
            return Ok(());
        }
        Some(ref payload) => {
            if let Some(ref file_path) = payload.file {
                // Full build mode
                let fw_data = if file_path == "-" {
                    let mut buf = Vec::new();
                    std::io::stdin().read_to_end(&mut buf)?;
                    eprintln!("Read {} bytes from stdin", buf.len());
                    buf
                } else {
                    fs::read(file_path)?
                };

                let encrypt_paths: Vec<PathBuf> = payload
                    .encrypt
                    .as_ref()
                    .map(|e| e.device_keys.clone())
                    .unwrap_or_default();

                let (digest, fw_size, processed, enc_info, cek) =
                    process_payload(&fw_data, payload.compress, &encrypt_paths)?;
                (digest, fw_size, Some(processed), enc_info, cek)
            } else if let (Some(ref digest_hex), Some(size)) = (&payload.digest, payload.size) {
                // Reference build mode
                let digest = parse_digest_hex(digest_hex)?;
                let enc_info = payload
                    .encryption_info
                    .as_ref()
                    .map(|p| fs::read(p))
                    .transpose()
                    .map_err(|e| format!("read encryption_info: {e}"))?;
                (digest, size, None, enc_info, None)
            } else {
                return Err("payload section requires either 'file' or 'digest' + 'size'".into());
            }
        }
    };

    // Build the manifest
    let mut builder = ImageManifestBuilder::new()
        .component_id(comp_id)
        .sequence_number(desc.sequence_number)
        .payload_digest(&digest, fw_size);

    if let Some(sv) = desc.security_version {
        builder = builder.security_version(sv);
    }

    builder = apply_metadata(builder, desc.metadata.as_ref());

    if let Some(ref ei) = enc_info {
        builder = builder.encryption_info(ei);
    }

    // Payload URI and integration
    let payload_desc = desc.payload.as_ref().unwrap();
    let uri = payload_desc
        .uri
        .clone()
        .unwrap_or_else(|| "#firmware".to_string());
    builder = builder.payload_uri(uri.clone());

    if let Some(ref fp) = final_payload {
        if desc.output.payload.is_none() {
            // Integrated envelope
            builder = builder.integrated_payload(uri.clone(), fp.clone());
        }
    }

    let envelope = builder.build(&key)?;
    fs::write(&desc.output.manifest, &envelope)?;
    eprintln!(
        "Wrote manifest to {} ({} bytes)",
        desc.output.manifest.display(),
        envelope.len()
    );

    // Write separate payload + enc-info + CEK if requested
    if let Some(ref po) = desc.output.payload {
        if let Some(ref fp) = final_payload {
            fs::write(po, fp)?;
            eprintln!("Wrote payload to {} ({} bytes)", po.display(), fp.len());

            if let Some(ref ei) = enc_info {
                let ei_path = PathBuf::from(format!("{}.enc-info", po.display()));
                fs::write(&ei_path, ei)?;
                eprintln!(
                    "Wrote encryption info to {} ({} bytes)",
                    ei_path.display(),
                    ei.len()
                );
            }
            if let Some(ref cek_bytes) = cek {
                let cek_path = PathBuf::from(format!("{}.cek", po.display()));
                fs::write(&cek_path, cek_bytes)?;
                eprintln!("Wrote CEK to {} (SENSITIVE)", cek_path.display());
            }
        }
    }

    Ok(())
}

/// Build a multi-component SUIT manifest from a YAML descriptor.
fn build_multi_component_manifest(desc: manifest::ManifestDescriptor) -> Result<(), Box<dyn std::error::Error>> {
    use sumo_offboard::image_builder::{MultiComponentBuilder, ComponentSpec};

    let key_bytes = fs::read(&desc.signing_key)?;
    let key = CoseKey::from_cose_key_bytes(&key_bytes)?;

    let components = desc.components.unwrap();
    let mut builder = MultiComponentBuilder::new()
        .sequence_number(desc.sequence_number);

    if let Some(sv) = desc.security_version {
        builder = builder.security_version(sv);
    }
    if let Some(ref meta) = desc.metadata {
        if let Some(ref v) = meta.version { builder = builder.text_version(v); }
        if let Some(ref m) = meta.model_name { builder = builder.text_model_name(m); }
        if let Some(ref d) = meta.description { builder = builder.text_description(d); }
    }

    // Process each component
    for comp_desc in &components {
        let payload = &comp_desc.payload;
        let uri = payload.uri.clone().unwrap_or_else(|| "#firmware".into());

        if let Some(ref file_path) = payload.file {
            // Full build mode: read file, compress, encrypt
            let fw_data = if file_path == "-" {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            } else {
                fs::read(file_path)?
            };

            let encrypt_paths: Vec<std::path::PathBuf> = payload.encrypt
                .as_ref()
                .map(|e| e.device_keys.clone())
                .unwrap_or_default();

            let (digest, fw_size, processed, enc_info, cek) =
                process_payload(&fw_data, payload.compress, &encrypt_paths)?;

            builder = builder.add_component(ComponentSpec {
                id: comp_desc.id.to_vec(),
                digest: digest.to_vec(),
                size: fw_size,
                uri: uri.clone(),
                encryption_info: enc_info.clone(),
            });

            // Write separate payload if output.payloads specifies a path
            if let Some(ref payloads_map) = desc.output.payloads {
                if let Some(po) = payloads_map.get(&uri) {
                    fs::write(po, &processed)?;
                    eprintln!("Wrote payload to {} ({} bytes)", po.display(), processed.len());

                    if let Some(ref ei) = enc_info {
                        let ei_path = std::path::PathBuf::from(format!("{}.enc-info", po.display()));
                        fs::write(&ei_path, ei)?;
                        eprintln!("Wrote encryption info to {} ({} bytes)", ei_path.display(), ei.len());
                    }
                    if let Some(ref cek_bytes) = cek {
                        let cek_path = std::path::PathBuf::from(format!("{}.cek", po.display()));
                        fs::write(&cek_path, cek_bytes)?;
                        eprintln!("Wrote CEK to {} (SENSITIVE)", cek_path.display());
                    }
                }
            } else {
                // Integrated payload
                builder = builder.integrated_payload(uri.clone(), processed);
            }
        } else if let (Some(ref digest_hex), Some(size)) = (&payload.digest, payload.size) {
            // Reference build mode
            let digest = parse_digest_hex(digest_hex)?;
            let enc_info = payload.encryption_info
                .as_ref()
                .map(|p| fs::read(p))
                .transpose()
                .map_err(|e| format!("read encryption_info: {e}"))?;

            builder = builder.add_component(ComponentSpec {
                id: comp_desc.id.to_vec(),
                digest: digest.to_vec(),
                size,
                uri: uri.clone(),
                encryption_info: enc_info,
            });
        } else {
            return Err(format!(
                "component {:?}: need either 'file' or 'digest' + 'size'",
                comp_desc.id.to_vec()
            ).into());
        }
    }

    let envelope = builder.build(&key)?;
    fs::write(&desc.output.manifest, &envelope)?;
    eprintln!(
        "Wrote multi-component manifest to {} ({} bytes, {} components)",
        desc.output.manifest.display(),
        envelope.len(),
        components.len(),
    );

    Ok(())
}

/// Apply metadata fields from a YAML descriptor to an ImageManifestBuilder.
fn apply_metadata(
    mut builder: ImageManifestBuilder,
    metadata: Option<&manifest::MetadataDescriptor>,
) -> ImageManifestBuilder {
    let Some(meta) = metadata else {
        return builder;
    };
    if let Some(ref v) = meta.vendor_id {
        if let Ok(uuid) = parse_uuid(v) {
            builder = builder.vendor_id(uuid);
        }
    }
    if let Some(ref c) = meta.class_id {
        if let Ok(uuid) = parse_uuid(c) {
            builder = builder.class_id(uuid);
        }
    }
    if let Some(ref v) = meta.version {
        builder = builder.text_version(v);
    }
    if let Some(ref mn) = meta.model_name {
        builder = builder.text_model_name(mn);
    }
    if let Some(ref d) = meta.description {
        builder = builder.text_description(d);
    }
    if let Some(ref vn) = meta.vendor_name {
        builder = builder.text_vendor_name(vn);
    }
    if let Some(ref mi) = meta.model_info {
        builder = builder.text_model_info(mi);
    }
    builder
}
