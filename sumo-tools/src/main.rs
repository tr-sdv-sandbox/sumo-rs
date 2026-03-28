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
    Build {
        /// Signing key file (COSE_Key CBOR)
        #[arg(short = 'k', long)]
        signing_key: PathBuf,

        /// Firmware payload file
        #[arg(short, long)]
        firmware: PathBuf,

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

        /// Write encrypted payload to this file (instead of embedding)
        #[arg(long)]
        payload_output: Option<PathBuf>,
    },

    /// Inspect a SUIT envelope.
    Inspect {
        /// SUIT envelope file
        #[arg(short, long)]
        input: PathBuf,
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
        } => {
            let key_bytes = fs::read(&signing_key)?;
            let key = CoseKey::from_cose_key_bytes(&key_bytes)?;
            let fw_data = fs::read(&firmware)?;

            let crypto = RustCryptoBackend::new();
            let comp_id: Vec<String> = component.split(',').map(|s| s.to_string()).collect();

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

                // Auto-detect: EC2 keys → ECDH-ES+A128KW, symmetric → A128KW
                let is_ecdh = recipients.first().map_or(false, |r| r.public_key.is_ec2());

                let encrypted = if is_ecdh {
                    // Generate ephemeral sender key for ECDH
                    let sender_key = keygen::generate_device_key(keygen::ES256)?;
                    // Recipients need public keys only for ECDH
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

            // Compute digest of original firmware (pre-compression, pre-encryption)
            let digest = crypto.sha256(&fw_data);

            let mut builder = ImageManifestBuilder::new()
                .component_id(comp_id)
                .sequence_number(seq)
                .payload_digest(&digest, fw_data.len() as u64);

            if let Some(v) = vendor {
                builder = builder.vendor_id(parse_uuid(&v)?);
            }
            if let Some(c) = class {
                builder = builder.class_id(parse_uuid(&c)?);
            }
            if let Some(u) = uri {
                builder = builder.payload_uri(u);
            }
            if let Some(ei) = enc_info {
                builder = builder.encryption_info(&ei);
            }

            let envelope = builder.build(&key)?;
            fs::write(&output, &envelope)?;
            eprintln!("Wrote manifest to {} ({} bytes)", output.display(), envelope.len());

            if let Some(po) = payload_output {
                fs::write(&po, &final_payload)?;
                eprintln!("Wrote payload to {} ({} bytes)", po.display(), final_payload.len());
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
