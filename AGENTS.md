# sumo-rs Index

Rust SUIT library workspace for CBOR codec, crypto, onboard validation/processing, offboard builders, and `sumo-tool`.

## Where to look

- `README.md` — crate map, examples, standards references.
- `CLAUDE.md` — current contributor map and key design decisions.
- `Cargo.toml` — workspace membership and dependency versions.
- `sumo-codec/src/` — SUIT types, CBOR encode/decode, command sequences.
- `sumo-crypto/src/` — crypto traits and RustCrypto backend.
- `sumo-onboard/src/` — validation, streaming decrypt/decompress, platform traits.
- `sumo-offboard/src/` — image/campaign builders, encryption, keygen.
- `sumo-tools/` — CLI package and README.

## Essential commands

No component-local `mise` file is present; use Cargo from this submodule root.

```bash
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo run -p sumo-tools -- --help
```

Finding commands:

```bash
rg --files -g 'Cargo.toml' -g 'README*' -g 'CLAUDE.md'
rg -n "security_version|SecurityVersion|ImageManifestBuilder|CampaignBuilder|PlatformOps|CryptoBackend" sumo-* README.md CLAUDE.md
```

## Stack

- Rust workspace, SUIT CBOR model, RustCrypto-backed signing/AEAD/ECDH/HKDF.
- `no_std`-capable core crates with `alloc` for device-side paths.

## Guardrails

- Use typed enums/parameters from `sumo-codec`; do not hand-roll SUIT labels or raw strings.
- Preserve `security_version` as anti-rollback floor, separate from replay/order sequence numbers.
- Keep streaming crypto behavior byte-compatible with one-shot encryption/decryption.

## Gotchas

- `sumo-codec`, `sumo-crypto`, and `sumo-onboard` are intended for constrained/no-std paths.
- Campaign manifests are two-level: L1 campaign dependencies over L2 image manifests.

## Missing docs/specs to watch

- CLI usage beyond `sumo-tools/README.md` is sparse.
- Public API stability/versioning policy is not documented in this checkout.
