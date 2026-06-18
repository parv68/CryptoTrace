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
echo "  10 -- Full Regression Suite"
echo "============================================"
echo "  Validates core detection across all types"
echo ""

# ── HASH DETECTION ──
echo "-- Hash Detection --"

step "MD5 exact algorithm" \
    sh -c "ALG=\$(get_json '5d41402abc4b2a76b9719d911017c592' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'MD5'"

step "MD5 Critical risk" \
    sh -c "RISK=\$(get_json '5d41402abc4b2a76b9719d911017c592' | jq -r '.risk_level'); \
    test \"\$RISK\" = 'Critical'"

step "SHA1 High risk" \
    sh -c "RISK=\$(get_json 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3' | jq -r '.risk_level'); \
    test \"\$RISK\" = 'High'"

step "SHA256 Low risk" \
    sh -c "RISK=\$(get_json 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' | jq -r '.risk_level'); \
    test \"\$RISK\" = 'Low'"

step "NTLM uppercase hex" \
    sh -c "ALG=\$(get_json '209C6174DA490CAEB422F3FA5A7AE634' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'NTLM'"

step "bcrypt prefix" \
    sh -c "ALG=\$(get_json '\$2a\$12\$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Q4p0F0n0Z0v0y0W0' | jq -r '.algorithm'); \
    echo \"\$ALG\" | grep -qi 'bcrypt'"

# ── ENCODING DETECTION ──
echo "-- Encoding Detection --"

step "Base64 standard" \
    sh -c "ALG=\$(get_json 'SGVsbG8gV29ybGQ=' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Base64'"

step "Hex standard" \
    sh -c "ALG=\$(get_json '48656C6C6F20576F726C64' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Hex'"

step "URL encoding" \
    sh -c "ALG=\$(get_json 'Hello%20World%21' | jq -r '.algorithm'); \
    test \"\$ALG\" = 'URLEncoding'"

step "Encoding confidence >= 0.90" \
    sh -c "CONF=\$(get_json 'SGVsbG8gV29ybGQ=' | jq -r '.confidence'); \
    awk \"BEGIN { exit (!(\$CONF > 0.90)) }\""

# ── ENTROPY & RISK ──
echo "-- Entropy & Risk --"

step "Entropy in valid range" \
    sh -c "ENT=\$(get_json 'SGVsbG8gV29ybGQ=' | jq -r '.entropy'); \
    awk \"BEGIN { exit (!(\$ENT >= 0.0 && \$ENT <= 8.0)) }\""

step "High-entropy plaintext NOT Critical" \
    sh -c "RISK=\$(get_json 'The quick brown fox jumps over the lazy dog' | jq -r '.risk_level'); \
    test \"\$RISK\" != 'Critical'"

# ── JSON STRUCTURE ──
echo "-- JSON Structure --"

step "JSON required fields" \
    sh -c "JSON=\$(get_json '5d41402abc4b2a76b9719d911017c592'); \
    echo \"\$JSON\" | jq -e '.input_hash and .entropy and .detected_type and .algorithm and .confidence and .risk_level and .signals' >/dev/null"

step "JSON signal sub-fields" \
    sh -c "JSON=\$(get_json '5d41402abc4b2a76b9719d911017c592'); \
    echo \"\$JSON\" | jq -e '.signals.entropy and .signals.block_alignment and .signals.magic_bytes and .signals.length_pattern' >/dev/null"

step "Engine version format" \
    sh -c "VER=\$(get_json '5d41402abc4b2a76b9719d911017c592' | jq -r '.engine_version'); \
    echo \"\$VER\" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'"

# ── EXPLAIN MODE ──
echo "-- Explain Mode --"

step "Explain shows Primary Drivers" \
    sh -c "cryptotrace analyze --explain '5d41402abc4b2a76b9719d911017c592' 2>/dev/null | grep -q 'Primary Drivers'"

step "Explain shows Related CVEs" \
    sh -c "cryptotrace analyze --explain '5d41402abc4b2a76b9719d911017c592' 2>/dev/null | grep -q 'Related CVEs'"

# ── DEEP MODE ──
echo "-- Deep Mode --"

step "Deep shows Layer Tree" \
    sh -c "cryptotrace analyze --deep 'SGVsbG8gV29ybGQ=' 2>/dev/null | grep -q 'Layer Tree'"

step "Deep output includes sub-layers" \
    sh -c "cryptotrace analyze --deep 'NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0' 2>/dev/null | grep -q '├─\|└─\|\[0\]'"

# ── FILE ANALYSIS ──
echo "-- File Analysis --"

step "File analysis source type" \
    sh -c "SRC=\$(cryptotrace analyze --json Cargo.toml 2>/dev/null | jq -r '.source_type'); \
    test \"\$SRC\" = 'File'"

echo ""
echo "============================================"
echo "  Regression Results: $PASSED/$TOTAL passed"
echo "============================================"
exit $FAILED
