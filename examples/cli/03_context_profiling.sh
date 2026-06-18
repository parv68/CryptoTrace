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

get_json_ctx() {
    cryptotrace analyze --json --context "$1" "$2" 2>/dev/null
}

HASH="5d41402abc4b2a76b9719d911017c592"

echo "============================================"
echo "  03 -- Cross-Context Threat Profiling"
echo "============================================"

# 3.1
step "Forensics context" \
    sh -c "CTX=\$(get_json_ctx 'forensics' \"$HASH\" | jq -r '.detection_context'); \
    test \"\$CTX\" = 'Forensics'"

# 3.2
step "Malware context" \
    sh -c "CTX=\$(get_json_ctx 'malware' \"$HASH\" | jq -r '.detection_context'); \
    test \"\$CTX\" = 'Malware'"

# 3.3
step "Password context" \
    sh -c "CTX=\$(get_json_ctx 'password' \"$HASH\" | jq -r '.detection_context'); \
    test \"\$CTX\" = 'Password'"

# 3.4
step "All contexts detect MD5" \
    sh -c " \
    A=\$(get_json_ctx 'forensics' \"$HASH\" | jq -r '.algorithm'); \
    B=\$(get_json_ctx 'malware'   \"$HASH\" | jq -r '.algorithm'); \
    C=\$(get_json_ctx 'password'  \"$HASH\" | jq -r '.algorithm'); \
    test \"\$A\" = 'MD5' && test \"\$B\" = 'MD5' && test \"\$C\" = 'MD5'"

# 3.5
step "Risk level consistent across contexts" \
    sh -c " \
    A=\$(get_json_ctx 'forensics' \"$HASH\" | jq -r '.risk_level'); \
    B=\$(get_json_ctx 'malware'   \"$HASH\" | jq -r '.risk_level'); \
    C=\$(get_json_ctx 'password'  \"$HASH\" | jq -r '.risk_level'); \
    test \"\$A\" = 'Critical' && test \"\$B\" = 'Critical' && test \"\$C\" = 'Critical'"

# 3.6
step "JSON engine_version present" \
    sh -c "VER=\$(get_json_ctx 'forensics' \"$HASH\" | jq -r '.engine_version'); \
    echo \"\$VER\" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+'"

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
