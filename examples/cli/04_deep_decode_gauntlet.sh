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

HEX="48656C6C6F20576F726C64"
B64_OF_HEX="NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0"
GZIP_B64="H4sIAAAAAAAAA8pIzcnJBwCkCAA5BAAAAA=="

echo "============================================"
echo "  04 -- Deep Recursive Decode Gauntlet"
echo "============================================"

# 4.1
step "Base64 decode shows layer tree" \
    sh -c "cryptotrace analyze --deep \"$B64_OF_HEX\" 2>/dev/null | grep -q 'Layer Tree'"

# 4.2
step "Hex decode shows layer tree" \
    sh -c "cryptotrace analyze --deep \"$HEX\" 2>/dev/null | grep -q 'Layer Tree'"

# 4.3
step "gzip+base64 2-layer decode" \
    sh -c "cryptotrace analyze --deep \"$GZIP_B64\" 2>/dev/null | grep -q '\[1\]'"

# 4.4
step "Top layer is Base64 for gzip-b64 input" \
    sh -c "ALG=\$(cryptotrace analyze --json \"$GZIP_B64\" 2>/dev/null | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Base64'"

# 4.5
step "Non-deep does not show layer tree" \
    sh -c "cryptotrace analyze \"$B64_OF_HEX\" 2>/dev/null | grep -vq 'Layer Tree'"

# 4.6
step "Deep adds additional output vs normal" \
    sh -c " \
    NORMAL=\$(cryptotrace analyze \"$B64_OF_HEX\" 2>/dev/null | wc -c); \
    DEEP=\$(cryptotrace analyze --deep \"$B64_OF_HEX\" 2>/dev/null | wc -c); \
    test \$DEEP -gt \$NORMAL"

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
