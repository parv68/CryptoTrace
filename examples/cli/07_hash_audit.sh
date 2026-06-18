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
echo "  07 -- Weak Hash CVE Audit"
echo "============================================"

MD5="5d41402abc4b2a76b9719d911017c592"
SHA1="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
NTLM="209C6174DA490CAEB422F3FA5A7AE634"
SHA512="cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

# 7.1
step "MD5 detected" \
    sh -c "ALG=\$(get_json \"$MD5\" | jq -r '.algorithm'); test \"\$ALG\" = 'MD5'"

# 7.2
step "MD5 Critical risk" \
    sh -c "RISK=\$(get_json \"$MD5\" | jq -r '.risk_level'); test \"\$RISK\" = 'Critical'"

# 7.3
step "SHA1 detected" \
    sh -c "ALG=\$(get_json \"$SHA1\" | jq -r '.algorithm'); test \"\$ALG\" = 'SHA1'"

# 7.4
step "SHA1 High risk" \
    sh -c "RISK=\$(get_json \"$SHA1\" | jq -r '.risk_level'); test \"\$RISK\" = 'High'"

# 7.5
step "SHA256 Low risk" \
    sh -c "RISK=\$(get_json \"$SHA256\" | jq -r '.risk_level'); test \"\$RISK\" = 'Low'"

# 7.6
step "NTLM Critical risk" \
    sh -c "RISK=\$(get_json \"$NTLM\" | jq -r '.risk_level'); test \"\$RISK\" = 'Critical'"

# 7.7
step "SHA512 Low risk" \
    sh -c "RISK=\$(get_json \"$SHA512\" | jq -r '.risk_level'); test \"\$RISK\" = 'Low'"

# 7.8
step "MD5 explain shows CVEs" \
    sh -c "cryptotrace analyze --explain \"$MD5\" 2>/dev/null | grep -q 'CVE-'"

# 7.9
step "MD5 explain shows collision warning" \
    sh -c "cryptotrace analyze --explain \"$MD5\" 2>/dev/null | grep -q 'collision'"

# 7.10
step "MD5 confidence >= 0.90" \
    sh -c "CONF=\$(get_json \"$MD5\" | jq -r '.confidence'); \
    awk \"BEGIN { exit (!(\$CONF > 0.90)) }\""

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
