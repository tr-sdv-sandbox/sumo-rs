//! sumo-tool: CLI for SUIT firmware update manifest operations.

use std::fs;
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
    Build {
        /// Signing key file (COSE_Key CBOR)
        #[arg(short = 'k', long)]
        signing_key: PathBuf,

        /// Firmware payload file (omit for reference builds with --payload-digest)
        #[arg(short, long)]
        firmware: Option<PathBuf>,

        /// Output envelope file
        #[arg(short, long)]
        output: PathBuf,

        /// Component ID segments (e.g., "ecu-a,firmware")
        #[arg(short, long)]
        component: String,

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

    /// Attach a payload to a reference manifest, creating an integrated envelope.
    ///
    /// Takes a small reference manifest and a separate payload file, and produces
    /// a new envelope with the payload embedded under the "#firmware" key.
    /// The manifest signature is preserved (it covers only the manifest, not payloads).
    Attach {
        /// Reference manifest file (SUIT envelope without integrated payload)
        #[arg(short, long)]
        manifest: PathBuf,

        /// Payload file to embed
        #[arg(short, long)]
        payload: PathBuf,

        /// Output envelope file (manifest + integrated payload)
        #[arg(short, long)]
        output: PathBuf,

        /// Payload key in the envelope (default: "#firmware")
        #[arg(long, default_value = "#firmware")]
        key: String,
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
            let key_bytes = fs::read(&signing_key)?;
            let key = CoseKey::from_cose_key_bytes(&key_bytes)?;
            let comp_id: Vec<String> = component.split(',').map(|s| s.to_string()).collect();

            // Two modes: firmware file (full build) or digest+size (reference build)
            let (digest, fw_size, final_payload, enc_info) = if let Some(ref fw_path) = firmware {
                if payload_digest_hex.is_some() || payload_size.is_some() {
                    return Err("cannot use --firmware with --payload-digest/--payload-size".into());
                }

                let fw_data = fs::read(fw_path)?;
                let crypto = RustCryptoBackend::new();

                // Optionally compress
                let payload = if compress {
                    eprintln!("Compressing firmware ({} bytes)...", fw_data.len());
                    encryptor::compress_firmware(&fw_data, 3)?
                } else {
                    fw_data.clone()
                };

                // Optionally encrypt
                let (final_payload, enc_info) = if let Some(ref key_files) = encrypt {
                    let recipients: Vec<Recipient> = key_files
                        .split(',')
                        .map(|path| {
                            let kb = fs::read(path.trim())
                                .unwrap_or_else(|_| panic!("cannot read key file: {path}"));
                            let dk = CoseKey::from_cose_key_bytes(&kb)
                                .unwrap_or_else(|_| panic!("invalid key file: {path}"));
                            Recipient {
                                public_key: dk,
                                kid: path.trim().as_bytes().to_vec(),
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
                    (encrypted.ciphertext, Some(encrypted.encryption_info))
                } else {
                    (payload, None)
                };

                let digest = crypto.sha256(&fw_data);
                (digest, fw_data.len() as u64, Some(final_payload), enc_info)
            } else {
                // Reference build mode — no firmware file
                let digest_hex = payload_digest_hex
                    .ok_or("--payload-digest required when --firmware is omitted")?;
                let size = payload_size
                    .ok_or("--payload-size required when --firmware is omitted")?;
                if compress || encrypt.is_some() {
                    return Err("--compress/--encrypt require --firmware".into());
                }

                let digest_bytes = hex::decode(&digest_hex)
                    .map_err(|e| format!("invalid --payload-digest hex: {e}"))?;
                if digest_bytes.len() != 32 {
                    return Err("--payload-digest must be 64 hex chars (32 bytes SHA-256)".into());
                }
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&digest_bytes);

                // Load encryption_info from file if provided
                let enc_info = encryption_info_path
                    .map(|p| fs::read(&p))
                    .transpose()
                    .map_err(|e| format!("read --encryption-info: {e}"))?;

                (digest, size, None, enc_info)
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
                    // No --payload-output: embed payload in manifest (integrated envelope)
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

                    // Also write encryption_info for reuse by reference builds
                    if let Some(ref ei) = enc_info {
                        let ei_path = PathBuf::from(format!("{}.enc-info", po.display()));
                        fs::write(&ei_path, ei)?;
                        eprintln!("Wrote encryption info to {} ({} bytes)", ei_path.display(), ei.len());
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
            let manifest_data = fs::read(&manifest)?;
            let payload_data = fs::read(&payload)?;
            eprintln!("Attaching payload ({} bytes) as {:?}", payload_data.len(), key);

            // Work at raw CBOR level to preserve the original signature.
            // The envelope is a CBOR map — we just append a new text-keyed entry.
            let value: ciborium::Value = ciborium::de::from_reader(manifest_data.as_slice())
                .map_err(|e| format!("failed to decode CBOR: {e}"))?;

            let entries = match value {
                ciborium::Value::Map(entries) => entries,
                _ => return Err("envelope is not a CBOR map".into()),
            };

            let mut new_entries = entries;
            new_entries.push((
                ciborium::Value::Text(key),
                ciborium::Value::Bytes(payload_data),
            ));

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
    }

    Ok(())
}
