# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

This project is currently in early development (Phase 1). If you discover a
security vulnerability, please open a GitHub issue with the label `security`.

Do **not** publicly disclose vulnerabilities until they have been addressed.

## Security Design

### Sandboxing (Phase 5)
Risky parsing operations (decompression, ASN.1, untrusted binary parsing) are
executed in isolated subprocesses via Windows Job Objects. If a worker process
crashes or is compromised, the main analysis pipeline remains unaffected.

### Input Limits
- Maximum file size: 50 MB
- Maximum string input: 10 MB
- Null bytes are rejected in strings, warned in binary
- Path traversal attempts are blocked

### No Network by Default
All cloud/AI features are opt-in. The engine operates fully air-gapped with
no network calls unless explicitly configured.

### AI Safety
- Structured output (no freeform generation)
- Per-field JSON validation to prevent hallucination
- All AI output flagged as non-authoritative
