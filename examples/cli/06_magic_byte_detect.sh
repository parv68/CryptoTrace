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

cleanup() {
    rm -f /tmp/test_*.bin /tmp/test_plain.txt 2>/dev/null
}
trap cleanup EXIT

echo "============================================"
echo "  06 -- Magic Byte Signature Detection"
echo "============================================"

# Create test files with real magic bytes
printf '\x25\x50\x44\x46\x2D\x31\x2E\x34' > /tmp/test_pdf.bin
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > /tmp/test_png.bin
printf '\x1F\x8B\x08\x00\x00\x00\x00\x00' > /tmp/test_gzip.bin
printf '\x7F\x45\x4C\x46\x02\x01\x01\x00' > /tmp/test_elf.bin
printf '\x50\x4B\x03\x04'               > /tmp/test_zip.bin
printf '\xFF\xD8\xFF\xE0'               > /tmp/test_jpeg.bin
printf '\x42\x5A\x68'                   > /tmp/test_bz2.bin
printf '\x28\xB5\x2F\xFD'               > /tmp/test_zstd.bin
echo "This is plain text content"        > /tmp/test_plain.txt

# 6.1-6.8
step "PDF magic byte detection" \
    sh -c "cryptotrace analyze --json /tmp/test_pdf.bin 2>/dev/null | grep -qi 'algorithm.*pdf'"

step "PNG magic byte detection" \
    sh -c "cryptotrace analyze --json /tmp/test_png.bin 2>/dev/null | grep -qi 'algorithm.*png'"

step "GZIP magic byte detection" \
    sh -c "cryptotrace analyze --json /tmp/test_gzip.bin 2>/dev/null | grep -qi 'algorithm.*GZIP\|algorithm.*gzip'"

step "ELF magic byte detection" \
    sh -c "cryptotrace analyze --json /tmp/test_elf.bin 2>/dev/null | grep -qi 'algorithm.*ELF\|algorithm.*elf'"

step "JPEG magic byte detection" \
    sh -c "cryptotrace analyze --json /tmp/test_jpeg.bin 2>/dev/null | grep -qi 'algorithm.*JPEG\|algorithm.*jpeg\|algorithm.*jpg'"

step "ZIP magic byte detection" \
    sh -c "cryptotrace analyze --json /tmp/test_zip.bin 2>/dev/null | grep -qi 'algorithm.*ZIP\|algorithm.*zip'"

step "Plaintext no false positive" \
    sh -c "TYPE=\$(cryptotrace analyze --json /tmp/test_plain.txt 2>/dev/null | jq -r '.detected_type'); \
    test \"\$TYPE\" = 'plaintext' -o \"\$TYPE\" = 'Unknown'"

echo ""
echo "Results: $PASSED/$TOTAL passed"
exit $FAILED
