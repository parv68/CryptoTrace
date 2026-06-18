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
echo "  01 -- Attack Chain Reconstruction"
echo "============================================"

HASH="5d41402abc4b2a76b9719d911017c592"
B64="SGVsbG8gV29ybGQ="
HEX="48656C6C6F"
DEEP="NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0"

# 1.1
step "MD5 hash detection" \
    sh -c "ALG=\$(get_json \"$HASH\" | jq -r '.algorithm'); \
    test \"\$ALG\" = 'MD5'"

# 1.2
step "MD5 Critical risk" \
    sh -c "RISK=\$(get_json \"$HASH\" | jq -r '.risk_level'); \
    test \"\$RISK\" = 'Critical'"

# 1.3
step "Base64 encoding detection" \
    sh -c "ALG=\$(get_json \"$B64\" | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Base64'"

# 1.4
step "Hex encoding detection" \
    sh -c "ALG=\$(get_json \"$HEX\" | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Hex'"

# 1.5
step "Recursive decode layer tree" \
    sh -c "cryptotrace analyze --deep \"$DEEP\" 2>/dev/null | grep -q 'Layer Tree'"

# 1.6
step "Explain shows CVEs" \
    sh -c "cryptotrace analyze --explain \"$HASH\" 2>/dev/null | grep -q 'CVE-'"

# 1.7
step "Explain shows collision warning" \
    sh -c "cryptotrace analyze --explain \"$HASH\" 2>/dev/null | grep -q 'collision'"

# 1.8
step "JSON confidence threshold" \
    sh -c "CONF=\$(get_json \"$HASH\" | jq -r '.confidence'); \
    awk \"BEGIN { exit (!(\$CONF > 0.90)) }\""

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
