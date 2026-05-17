# CryptoTrace

**Cryptographic Fingerprinting & Data Classification Engine**

CryptoTrace analyses files and strings to detect cryptographic fingerprints — hashes, encodings, compressed data, encrypted blobs, and embedded high-entropy payloads. It explains *why* something is flagged via signal breakdown, recursive layer unwrapping, and provisional confidence scoring.

---

## Features

- **Hash detection** — MD5, SHA1, SHA256, SHA512, bcrypt, Argon2id, NTLM, UUID (with whitespace stripping and disambiguation)
- **Encoding detection** — Base64, Hex, URL Encoding, Base32 (with confidence scoring and decode preview)
- **Compression detection** — GZIP, BZ2, Zstd, XZ, ZIP magic bytes + resource-limited decompression with expansion ratio guard (100:1 max)
- **Encryption heuristics** — OpenSSL AES (`Salted__` prefix), RSA PEM headers, generic high-entropy + block alignment detection
- **Entropy analysis** — Shannon entropy (0.0–8.0) + 4KB sliding window with 2KB stride to find embedded high-entropy regions
- **Magic byte registry** — 50-entry YAML-driven signature database covering compression, documents, images, audio, video, executables, archives, disk images, cryptographic keys, fonts, databases, and bytecode formats
- **Recursive layer analysis** — unwraps nested encoding/compression with cycle detection, depth limit (10), timeout (30s), and expansion ratio guard
- **Provisional confidence engine** — multi-signal weighting with entropy consistency (Phase 3 will add Platt scaling calibration)
- **Risk classification** — Critical / High / Medium / Low / Unknown with category-based defaults and user override support
- **Audit logging** — structured tracing events for every analysis
- **Input sanitization** — size limits (50 MB files, 10 MB strings), null byte policy, path traversal prevention, symlink detection
- **Sandbox scaffold** — Win32 Job Object isolation for subprocess workers (Phase 5)
- **CLI** — `analyze`, `update`, `version`, `cache`, `config` commands via clap derive
- **JSON output** — machine-readable analysis results with all signals and metadata

---

## Installation

### Prerequisites

- **Rust 1.95.0** or later (stable toolchain)
- **Windows** (x86_64-pc-windows-msvc) — primary target; Linux/macOS cross-compilation configured in `rust-toolchain.toml`

### Build from source

```bash
git clone https://github.com/your-org/cryptotrace.git
cd cryptotrace
cargo build --release
```

The release binary will be at `target/release/cryptotrace.exe` (~1.7 MB). A worker binary is also produced at `target/release/cryptotrace-worker.exe` (~130 KB) for Phase 5 subprocess isolation.

### Verify

```bash
cryptotrace version
```

Expected output:
```
CryptoTrace v0.1.0
Engine: 0.1.0
Signature DB: 1.0.0
```

---

## Usage

### Analyze a string

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99"
```

Detects MD5 hash:
```
═══════════════════════════════════════
 CryptoTrace Analysis Report
═══════════════════════════════════════

 Input:      3f2cd8e57b096fe7e4a78a5627e34ca3
 Entropy:    3.80 / 8.00
 Risk Level: Critical
 Source:     String

 Detection:  MD5
 Type:       hash
 Confidence: 94% (provisional — Phase 1 engine)

 Signals:
   entropy            3.80
   block_alignment    0.00
   magic_bytes        0.00
   length_pattern     1.00
   charset_purity     1.00
   window_variance    0.00

 Weakness:   collision_vulnerable, rainbow_table_crackable

 Recommendation:
   Replace with bcrypt (cost ≥ 12) or Argon2id.

═══════════════════════════════════════
```

### Analyze a file

```bash
cryptotrace analyze suspicious_file.bin
```

If the path exists, it is read and analysed as a file.

### Magic byte detection

```bash
cryptotrace analyze "%PDF-1.4"
```

Detects PDF document type from the `%PDF` magic bytes:
```
 Detection:  pdf
 Type:       document
 Risk Level: Medium

 Signals:
   ...
   magic_bytes        1.00
   ...
```

### JSON output

```bash
cryptotrace analyze "5f4dcc3b5aa765d61d8327deb882cf99" --json
```

Returns structured JSON with all fields:
```json
{
  "input_hash": "3f2cd8e57b096fe7e4a78a5627e34ca3f885ad65a56e61c287cf4211bbc5949f",
  "source_type": "String",
  "entropy": 3.804,
  "detected_type": "hash",
  "algorithm": "MD5",
  "confidence": 0.945,
  "risk_level": "Critical",
  "signals": { ... },
  "layers": [],
  "engine_version": "0.1.0",
  "signature_db_version": "1.0.0"
}
```

### Threat context

```bash
cryptotrace analyze suspicious_entry.dll --context malware
cryptotrace analyze hash.txt --context password
cryptotrace analyze unknown.bin --context forensics
```

Adjusts classification heuristics for the given context (default: `forensics`).

### Recursive analysis

```bash
cryptotrace analyze encoded_payload.bin --deep
```

Unwraps nested layers (Base64 → GZIP → ...) up to depth 10 with timeout and expansion ratio guards.

### Signature database management

```bash
# Check current version
cryptotrace update

# Import an update from a local file (air-gap mode)
cryptotrace update --from-file /path/to/updated-registry.yaml

# Roll back to previous version
cryptotrace update --rollback
```

### Cache and configuration

```bash
cryptotrace cache clear
cryptotrace config show
```

---

## Signal Breakdown

Each analysis returns a `SignalBreakdown` with these components:

| Signal | Range | Description |
|--------|-------|-------------|
| `entropy` | 0.0–8.0 | Shannon entropy of the input |
| `block_alignment` | 0.0–1.0 | How well data aligns to AES/RSA block sizes |
| `magic_bytes` | 0.0–1.0 | Confidence from signature registry match |
| `length_pattern` | 0.0–1.0 | How well length matches expected hash/encoding sizes |
| `charset_purity` | 0.0–1.0 | Portion of input matching expected character set |
| `window_variance` | 0.0+ | Variance in sliding-window entropy scores |
| `byte_distribution` | 0.0–1.0 | Uniformity of byte frequency distribution (Phase 3) |

---

## Architecture

```
src/
├── main.rs                  # Binary entrypoint
├── lib.rs                   # Crate root (public module exports)
├── cli.rs                   # CLI definition (clap derive)
├── types.rs                 # Core structs: DetectionResult, SignalBreakdown, etc.
├── error.rs                 # CryptoTraceError enum (thiserror)
├── analyzers/
│   ├── file.rs              # Full detection pipeline for files and bytes
│   ├── string.rs            # String-specific analysis
│   └── recursive.rs         # Recursive layer unwrapping
├── core/
│   ├── entropy.rs           # Shannon entropy + classification
│   ├── sliding_entropy.rs   # 4KB rolling-window entropy
│   ├── hashing.rs           # Hash format detection
│   ├── encoding.rs          # Encoding format detection
│   ├── compression.rs       # Compression detection + decompression
│   ├── encryption.rs        # Encryption heuristics
│   └── confidence.rs        # Provisional confidence engine
├── signatures/
│   └── mod.rs               # Magic byte registry (YAML-driven)
├── intelligence/
│   ├── risk.rs              # Risk level resolution
│   ├── prompt.rs            # AI narrative stub (Phase 4)
│   └── audit.rs             # Structured audit logging
├── reports/
│   ├── terminal.rs          # Formatted terminal output
│   └── json.rs              # JSON serialization
├── sanitization/
│   ├── guard.rs             # InputGuard (size, null bytes, path traversal)
│   └── sandbox.rs           # Process isolation (Win32 Job Object)
├── api/                     # REST API stubs (Phase 6)
│   ├── mod.rs
│   ├── auth.rs
│   └── routes.rs
├── providers/               # AI provider trait (Phase 4)
│   └── mod.rs
├── update.rs                # Signature database update manager
├── cache.rs                 # LRU cache for dedup and AI narratives
└── workers.rs               # Worker pool (Phase 5)
```

---

## Security

- **Air-gapped by default** — no network calls unless explicitly configured
- **All AI features opt-in** — disabled until a provider is configured in `cryptotrace.toml`
- **Input limits** — 50 MB files, 10 MB strings, null bytes rejected in strings
- **Decompression guards** — 100:1 expansion ratio limit, 100 MB output cap
- **Recursion guards** — depth limit (10), timeout (30s), cycle detection via hash set
- **Sandbox isolation** — risky parsers run in isolated subprocesses via Win32 Job Objects (Phase 5)
- **Structured AI output** — per-field JSON validation prevents hallucination (Phase 4)

See [`SECURITY.md`](SECURITY.md) for the full security policy.

---

## Configuration

Create a `cryptotrace.toml` file in the working directory or in `%APPDATA%/cryptotrace/`:

```toml
[analysis]
context = "forensics"
max_file_size = 52428800
max_string_size = 10485760
deep = false

[signatures]
registry_path = ""
auto_update = false

[sandbox]
enabled = false
max_workers = 4
timeout_seconds = 30

[ai]
# provider = "openai"
# api_key = "sk-..."

[cache]
max_ai_entries = 100
dedup_enabled = true
max_dedup_entries = 1000

[api]
enabled = false
bind = "127.0.0.1:8080"
rate_limit = 60

[logging]
level = "info"
format = "pretty"
```

See [`cryptotrace.toml.example`](cryptotrace.toml.example) for a complete reference.

---

## Development

### Running tests

```bash
cargo test
```

70+ unit tests covering all detection modules, sanitization, cache, signatures, and update management.

### Building

```bash
cargo build                 # debug
cargo build --release       # release (LTO, stripped)
```

### Code style

```bash
cargo fmt
cargo clippy
```

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Core engine (entropy, hashing, encoding, compression detection), CLI, reports, tests | Done |
| 2 | Magic byte registry (50 entries), real decompression (GZIP/BZ2/Zstd/XZ), update manager | Done |
| 3 | Calibrated confidence (Platt scaling), signal attribution, accuracy benchmarks | Planned |
| 4 | AI narrative generation (OpenAI/Anthropic/local), prompt validation | Planned |
| 5 | Subprocess sandbox for risky parsers, ASN.1/PEM/BER full parsing | Planned |
| 6 | REST API (axum), async job queue, rate limiting | Planned |
| 7 | GPG-signed signature updates, verified update channel | Planned |

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).
