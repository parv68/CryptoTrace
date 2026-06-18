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

PLAINTEXTS=(
    "The quick brown fox jumps over the lazy dog"
    "Hello World! This is a simple test with normal words"
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    "abcdefghijklmnopqrstuvwxyz"
    "1234567890 1234567890 1234567890"
    "GET /index.html HTTP/1.1"
    '{"name": "John", "age": 30, "city": "New York"}'
    "<html><body><h1>Welcome</h1></body></html>"
    "2024-01-15 10:30:45 ERROR Connection failed"
    "Monday Tuesday Wednesday Thursday Friday"
    "SELECT * FROM users WHERE id = 1"
    "https://api.github.com/repos/ParvLab/CryptoTrace"
    "user@example.com:password123:John:Doe"
    "The MD5 hash d41d8cd98f00b204e9800998ecf8427e is obsolete"
)

echo "============================================"
echo "  05 -- False Positive Benchmark"
echo "============================================"

# 5.1
step "All plaintexts return low confidence" \
    sh -c "
    FP=0
    TOTAL=0
    for txt in \"${PLAINTEXTS[@]}\"; do
        TOTAL=\$((TOTAL + 1))
        TYPE=\$(cryptotrace analyze --json \"\$txt\" 2>/dev/null | jq -r '.detected_type')
        if [ \"\$TYPE\" != 'plaintext' ] && [ \"\$TYPE\" != 'Unknown' ]; then
            FP=\$((FP + 1))
        fi
    done
    PCT=\$((FP * 100 / TOTAL))
    echo \"    FP rate: \$PCT% (\$FP/\$TOTAL)\"
    [ \$PCT -le 30 ]
    "

# 5.2
step "No hash detected in plain English" \
    sh -c "ALG=\$(cryptotrace analyze --json 'The quick brown fox jumps over the lazy dog' 2>/dev/null | jq -r '.algorithm'); \
    test \"\$ALG\" = 'Unknown' -o \"\$ALG\" = 'null'"

# 5.3
step "No confident false positives" \
    sh -c "
    for txt in \"${PLAINTEXTS[@]}\"; do
        JSON=\$(cryptotrace analyze --json \"\$txt\" 2>/dev/null)
        TYPE=\$(echo \"\$JSON\" | jq -r '.detected_type')
        CONF=\$(echo \"\$JSON\" | jq -r '.confidence')
        if [ \"\$TYPE\" != 'plaintext' ] && [ \"\$TYPE\" != 'Unknown' ] && [ \"\$(echo \"\$CONF > 0.8\" | bc -l 2>/dev/null)\" = '1' ]; then
            echo \"      High-conf FP: \$txt\"
            exit 1
        fi
    done
    exit 0
    "

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
