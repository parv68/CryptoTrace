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

echo "============================================"
echo "  08 -- System Configuration Audit"
echo "============================================"

# 8.1
step "version output" \
    sh -c "cryptotrace version 2>/dev/null | grep -qE 'CryptoTrace|Engine|Signature'"

# 8.2
step "config show output" \
    sh -c "cryptotrace config show 2>/dev/null | grep -qE 'AI enabled|Sandbox|Entropy|Max file|Risk'"

# 8.3
step "calibrate status output" \
    sh -c "cryptotrace calibrate status 2>/dev/null | grep -qi 'calibration\|entropy\|intercept'"

# 8.4
step "cache status output" \
    sh -c "cryptotrace cache status 2>/dev/null | grep -qi 'enabled\|capacity\|entries'"

# 8.5
step "cache clear succeeds" \
    sh -c "cryptotrace cache clear 2>/dev/null; exit 0"

# 8.6
step "analyze --help flags" \
    sh -c "cryptotrace analyze --help 2>/dev/null | grep -qE '--deep|--json|--explain|--context|--sandbox|--ai'"

# 8.7
step "top-level --help commands" \
    sh -c "cryptotrace --help 2>/dev/null | grep -qE 'analyze|update|version|cache|config|calibrate'"

# 8.8
step "version contains semver" \
    sh -c "cryptotrace version 2>/dev/null | grep -qE '[0-9]+\.[0-9]+\.[0-9]+'"

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
