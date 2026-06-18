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
echo "  02 -- Adversarial Evasion Detection"
echo "============================================"

# 2.1
step "Zero-entropy MD5 detection" \
    sh -c "ALG=\$(get_json '00000000000000000000000000000000' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'MD5'"

# 2.2
step "Over-padded base64" \
    sh -c "ALG=\$(get_json 'SGVsbG8gV29ybGQ====' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Base64'"

# 2.3
step "Ambiguous hex/base64" \
    sh -c "ALG=\$(get_json 'abc1237890deadbeef' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'MD5'"

# 2.4
step "Mixed encoding low confidence" \
    sh -c "CONF=\$(get_json '48656C6C6F=20 576F72=6C64' | jq -r '.confidence'); \
    awk \"BEGIN { exit (!(\$CONF < 0.5)) }\""

# 2.5
step "Random-looking high entropy" \
    sh -c "ENT=\$(get_json 'ecWUoO0a0Yb1zB2xR3vA4sD5fG6hJ7kL8zX9cV0bN' | jq -r '.entropy'); \
    awk \"BEGIN { exit (!(\$ENT > 4.0)) }\""

# 2.6
step "Plaintext low confidence" \
    sh -c "CONF=\$(get_json 'Hello World! This is a test.' | jq -r '.confidence'); \
    awk \"BEGIN { exit (!(\$CONF < 0.5)) }\""

# 2.7
step "URL encoding detection" \
    sh -c "ALG=\$(get_json 'Hello%20World%21' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'URLEncoding'"

# 2.8
step "UUID not Critical risk" \
    sh -c "RISK=\$(get_json '550e8400-e29b-41d4-a716-446655440000' | jq -r '.risk_level'); \
    test \"\$RISK\" != 'Critical'"

# 2.9
step "bcrypt prefix detection" \
    sh -c "ALG=\$(get_json '\$2a\$12\$LJ3m' | jq -r '.algorithm'); \
    echo \"\$ALG\" | grep -qi 'bcrypt'"

# 2.10
step "Base64 without padding" \
    sh -c "ALG=\$(get_json 'SGVsbG8gV29ybGQ' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Base64'"

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
