#!/usr/bin/env bash
set -euo pipefail

TOTAL=0
PASSED=0
FAILED=0

step() {
    local name="$1"
    shift
    TOTAL=$((TOTAL + 1))
    if "$@"; then
        echo "  PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "  FAIL: $name"
        FAILED=$((FAILED + 1))
    fi
}

get_json() {
    cryptotrace analyze --json "$1" 2>/dev/null
}

echo "============================================"
echo "  09 -- Real-World Payload Diversity"
echo "============================================"

# 9.1
step "Base64 API key" \
    sh -c "ALG=\$(get_json 'c2stcHJvai1hYmNkZWYxMjM0NTY3ODkw' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Base64'"

# 9.2
step "Hex encoded data" \
    sh -c "ALG=\$(get_json '48656C6C6F20576F726C6421' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Hex'"

# 9.3
step "Argon2id hash detection" \
    sh -c "ALG=\$(get_json '\$argon2id\$v=19\$m=65536,t=3,p=4\$c29tZXNhbHQ\$R9udBQxI1HQC' | jq -r '.algorithm'); \
    echo \"\$ALG\" | grep -qi 'argon'"

# 9.4
step "bcrypt hash detection" \
    sh -c "ALG=\$(get_json '\$2b\$10\$A5lRnIh0VoY1TqQFxZh6T.Uj8gH4mS3G9yX5N0dLq' | jq -r '.algorithm'); \
    echo \"\$ALG\" | grep -qi 'bcrypt'"

# 9.5
step "High entropy encryption-like" \
    sh -c "ENT=\$(get_json 'e6a5b3c4d2f1a8b7c9d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4' | jq -r '.entropy'); \
    awk \"BEGIN { exit (!(\$ENT > 3.5)) }\""

# 9.6
step "URL query parameters" \
    sh -c "cryptotrace analyze 'https://example.com/search?q=test' 2>/dev/null | grep -q 'Entropy'"

# 9.7
step "Salted OpenSSL ciphertext" \
    sh -c "ALG=\$(get_json 'U2FsdGVkX19ncmVlbiBpcyBnb29kIGZvciBoZWFsdGg=' | jq -r '.algorithm'); \
    echo \"\$ALG\" | grep -qiE 'AES|OpenSSL|Salted'"

# 9.8
step "PEM certificate-like detection" \
    sh -c "cryptotrace analyze '-----BEGIN CERTIFICATE-----' 2>/dev/null | grep -q 'Entropy'"

# 9.9
step "RSA private key-like detection" \
    sh -c "cryptotrace analyze '-----BEGIN RSA PRIVATE KEY-----' 2>/dev/null | grep -q 'Entropy'"

# 9.10
step "SHA256 of empty string" \
    sh -c "ALG=\$(get_json 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'SHA256'"

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
