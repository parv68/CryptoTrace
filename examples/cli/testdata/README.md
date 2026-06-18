# CryptoTrace Test Data Files

Usage: `cryptotrace analyze [--json] testdata/<file>`

## Categories

### 01 - Multi-Layer Obfuscation Chains (7 files)
Deeply nested encoding that tests recursive decode (`--deep`):
- `01_deep_b64_of_hex.txt` — Base64(Hex("cryptotrace"))
- `01_deep_hex_of_b64.txt` — Hex(Base64("cryptotrace"))
- `01_deep_b64_of_b64.txt` — Base64(Base64("cryptotrace"))
- `01_deep_hex_of_hex.txt` — Hex(Hex("cryptotrace"))
- `01_deep_b64_of_hex_of_b64.txt` — Base64(Hex(Base64("cryptotrace")))
- `01_deep_7layer_b64.txt` — Base64^3("cryptotrace")
- `01_deep_gzip_b64.txt` — Base64(gzip("Hello"))

### 02 - Real-World Malware Payloads (5 files)
- `02_cobaltstrike_config.txt` — Cobalt Strike beacon XML config (base64)
- `02_powershell_encoded.txt` — UTF-16LE base64 PowerShell encoded command
- `02_meterpreter_hex.txt` — Meterpreter shellcode (hex)
- `02_emotet_b64_wrapped.txt` — Emotet-style base64 with line breaks
- `02_ransomnote_b64.txt` — Ransom note text (base64)

### 03 - Adversarial / Evasion (6 files)
- `03_zerowidth_b64.txt` — Base64 with zero-width space characters
- `03_double_utf8.txt` — Double-UTF-8 encoded text (hex)
- `03_extra_padding_b64.txt` — Base64 with extra `=` signs
- `03_mixed_encoding_line.txt` — Hex + base64 + plaintext in one line
- `03_custom_alphabet_b64.txt` — Non-standard base64 alphabet
- `03_terminal_escape_b64.txt` — Terminal escape sequences mixed with base64

### 04 - Cryptographic Edge Cases (8 files)
- `04_argon2id_hash.txt` — Argon2id hash string
- `04_bcrypt_hash.txt` — bcrypt hash with cost=12
- `04_hmac_sha256_hex.txt` — HMAC-SHA256 output (hex)
- `04_asn1_der_hex.txt` — ASN.1/DER encoded public key (hex)
- `04_rsa_ciphertext_hex.txt` — RSA ciphertext (hex, 256 bytes)
- `04_jwt_token.txt` — JWT token (3 base64 segments)
- `04_pkcs7_padding_hex.txt` — PKCS#7 padded data (hex)
- `04_scrypt_output_hex.txt` — Scrypt KDF output (hex)

### 05 - Format Confusion & Boundaries (7 files)
- `05_ambiguous_hex_b64_b58.txt` — Valid as hex, base64, and Base58
- `05_short_input_1byte.txt` — Single character
- `05_short_input_2byte.txt` — Two characters
- `05_short_input_4byte.txt` — Four characters
- `05_long_b64_10k.txt` — ~10KB of base64 text
- `05_binary_random.txt` — Random-looking hex string
- `05_extreme_entropy_zeros.txt` — All zeros (entropy = 0)
- `05_high_entropy_random.txt` — High-entropy random alphanumeric

### 06 - Binary / Magic Byte Detection (11 files)
- `06_pdf_magic.bin` — PDF header (%PDF-1.4)
- `06_png_magic.bin` — PNG signature bytes
- `06_gzip_magic.bin` — GZIP magic (1F 8B 08)
- `06_elf_magic.bin` — ELF executable header
- `06_zip_magic.bin` — ZIP local file header
- `06_jpeg_magic.bin` — JPEG SOI marker
- `06_bz2_magic.bin` — BZ2 header
- `06_zstd_magic.bin` — Zstandard magic
- `06_polyglot_pdf_zip.bin` — PDF + ZIP polyglot
- `06_truncated_pdf_magic.bin` — Partial PDF header (3 bytes)
- `06_corrupted_png_magic.bin` — Bit-flipped PNG last byte

### 07 - Threshold Stressors & Edge Cases (9 files)
- `07_noise_with_payload.txt` — Large noise with small embedded base64
- `07_barely_b64_4chars.txt` — Minimal base64 (YQ==)
- `07_barely_hex_6chars.txt` — Minimal hex (616263)
- `07_low_entropy_long.txt` — 200+ repetitions of 'a'
- `07_confidence_stalemate.txt` — SHA256 detected as Hex (ambiguity)
- `07_pem_rsa_key.txt` — PEM RSA private key header
- `07_pem_certificate.txt` — PEM certificate header
- `07_pgp_message.txt` — PGP message block
- `07_partial_collision_16char.txt` — First 16 hex chars of SHA256
- `07_url_encoded.txt` — URL-encoded string

## Known Behavior Notes

- Binary files with null bytes (06_png, 06_gzip, 06_elf, 06_zip, 06_jpeg, 06_zstd) cause "Null bytes detected" errors — cryptotrace reads files as text strings
- BZ2 magic bytes (42 5A 68) may be misidentified as Z85 encoding
- PEM headers like "-----BEGIN RSA PRIVATE KEY-----" are not specifically detected
- JWT tokens may be detected as Z85 rather than JWT
