# sumo-tool

CLI for creating, signing, encrypting, and inspecting SUIT firmware update manifests (RFC 9124).

## Build

```bash
cargo build --release --package sumo-tools
# Binary at: target/release/sumo-tool
```

## Architecture

```
Server (offboard)                          Device (onboard)
─────────────────                          ────────────────
signing.key (private)                      signing.pub (trust anchor)
device.pub  (public)                       device.key  (private)

    │                                          │
    ▼                                          ▼
sumo-tool build                            validate manifest signature
  → encrypt firmware with device.pub       decrypt firmware with device.key
  → sign manifest with signing.key         verify digest, write firmware
  → output: manifest.suit + payload.enc
```

- **Signing keypair (ES256 or EdDSA)**: Server signs manifests with the private key. Devices verify with the public key (trust anchor).
- **Device keypair (P-256 ECDH)**: Server encrypts the firmware CEK with the device's public key (ECDH-ES+A128KW). Device decrypts with its private key.

## Quick Start

### 1. Generate keys

```bash
# Server signing keypair
sumo-tool keygen -a es256 -o signing.key -p signing.pub

# Device ECDH keypair
sumo-tool keygen -a es256 --device -o device.key -p device.pub
```

Provision `signing.pub` and `device.key` to the device.
Keep `signing.key` and `device.pub` on the server.

### 2. Build a signed + encrypted manifest

```bash
sumo-tool build \
    -k signing.key \
    -f firmware.bin \
    -o manifest.suit \
    -c ecu-a,firmware \
    -s 42 \
    --uri https://fw.example.com/v42/firmware.enc \
    --encrypt device.pub \
    --payload-output firmware.enc
```

This:
1. Computes SHA-256 digest of the firmware
2. Encrypts the firmware using ECDH-ES+A128KW with the device's public key
3. Builds the SUIT manifest with component ID, sequence number, URI, digest, and encryption info
4. Signs the manifest with the server's signing key (COSE_Sign1)
5. Writes the SUIT envelope to `manifest.suit` and the encrypted payload to `firmware.enc`

### 3. Build with compression

```bash
sumo-tool build \
    -k signing.key \
    -f firmware.bin \
    -o manifest.suit \
    -c ecu-a,firmware \
    -s 42 \
    --uri https://fw.example.com/v42/firmware.enc \
    --encrypt device.pub \
    --compress \
    --payload-output firmware.enc
```

Adds zstd compression before encryption. The device detects the zstd magic bytes after decryption and decompresses automatically.

### 4. Inspect a manifest

```bash
sumo-tool inspect -i manifest.suit
```

Output:
```
SUIT Envelope: manifest.suit
  Manifest version: 1
  Sequence number:  42
  Components:       1
  Dependencies:     0
  Signatures:       1
  Integrated payloads: 0
  Component 0: [ecu-a, firmware]
  Digest: Sha256 a1b2c3...
```

### 5. Build a campaign (multi-image update)

First build individual L2 image manifests, then combine into an L1 campaign:

```bash
# Build L2 manifests for each ECU
sumo-tool build -k signing.key -f ecu_a_fw.bin -o l2-a.suit \
    -c ecu-a,firmware -s 100 \
    --uri https://fw.example.com/ecu-a.enc \
    --encrypt device_a.pub --payload-output ecu-a.enc

sumo-tool build -k signing.key -f ecu_b_fw.bin -o l2-b.suit \
    -c ecu-b,firmware -s 100 \
    --uri https://fw.example.com/ecu-b.enc \
    --encrypt device_b.pub --payload-output ecu-b.enc

# Build L1 campaign referencing the L2 manifests
sumo-tool campaign -k signing.key -s 200 -o campaign.suit \
    -d "https://fw.example.com/l2-a.suit=l2-a.suit,https://fw.example.com/l2-b.suit=l2-b.suit"
```

For integrated payloads (L2 manifests embedded in the campaign envelope):

```bash
sumo-tool campaign -k signing.key -s 200 -o campaign.suit \
    -d "#l2-a=l2-a.suit,#l2-b=l2-b.suit"
```

## Command Reference

### `keygen`

Generate a signing or device key pair.

| Flag | Description | Default |
|------|-------------|---------|
| `-a, --algorithm` | `es256` or `eddsa` | `es256` |
| `-o, --output` | Private key output path (COSE_Key CBOR) | required |
| `-p, --public` | Public key output path | optional |
| `--device` | Generate ECDH device key instead of signing key | false |

### `build`

Build and sign an L2 image manifest.

| Flag | Description | Default |
|------|-------------|---------|
| `-k, --signing-key` | Signing private key file | required |
| `-f, --firmware` | Firmware binary file | required |
| `-o, --output` | Output manifest envelope file | required |
| `-c, --component` | Component ID segments, comma-separated | required |
| `-s, --seq` | Sequence number (for rollback protection) | `1` |
| `--vendor` | Vendor UUID (32 hex chars) | optional |
| `--class` | Class UUID (32 hex chars) | optional |
| `--uri` | Firmware payload fetch URI | optional |
| `--encrypt` | Device key files for encryption, comma-separated | optional |
| `--compress` | Compress with zstd before encryption | false |
| `--payload-output` | Write encrypted payload to file | optional |

Encryption auto-detects key type:
- **EC2 (P-256)** keys use ECDH-ES+A128KW
- **Symmetric** keys use A128KW

### `campaign`

Build and sign an L1 campaign manifest.

| Flag | Description | Default |
|------|-------------|---------|
| `-k, --signing-key` | Signing private key file | required |
| `-o, --output` | Output manifest envelope file | required |
| `-s, --seq` | Sequence number | `1` |
| `-d, --deps` | Dependencies: `URI=file` pairs, comma-separated | required |
| `--vendor` | Vendor UUID (32 hex chars) | optional |
| `--class` | Class UUID (32 hex chars) | optional |

Dependency format: `https://example.com/l2.suit=local.suit` for external, `#name=local.suit` for integrated.

### `inspect`

Inspect a SUIT envelope.

| Flag | Description |
|------|-------------|
| `-i, --input` | SUIT envelope file |

## Key Formats

All keys are stored as CBOR-encoded COSE_Key (RFC 9052). The binary format is compact and directly usable by the SUIT onboard library without conversion.

## Security Notes

- Signing keys should be stored securely (HSM, vault, etc.) in production
- Device private keys should never leave the device
- Sequence numbers must strictly increase to prevent rollback attacks
- The manifest digest (SHA-256) covers the entire manifest; the signature covers the digest
- Encrypted payloads use AES-128-GCM with per-manifest random CEK and IV
