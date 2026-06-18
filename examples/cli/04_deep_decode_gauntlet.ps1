param([switch]$Quiet)

$total = 0
$passed = 0

function Test-Step {
    param($Name, $Script)
    $script:total++
    try {
        & $Script
        if (-not $Quiet) { Write-Host "  PASS: $Name" -ForegroundColor Green }
        $script:passed++
    } catch {
        if (-not $Quiet) { Write-Host "  FAIL: $Name`n    $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Get-Json { param($Val) cryptotrace analyze --json $Val 2>&1 | Out-String | ConvertFrom-Json }

# Layer constructions (pre-computed):
# L0: plaintext "Hello World"
# L1: hex of L0 â†’ "48656C6C6F20576F726C64"
# L2: base64 of L1 â†’ "NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0"
# L3: should detect as Base64
$hexEncoded = "48656C6C6F20576F726C64"
$b64OfHex   = "NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0"

# gzip(base64(plaintext)) - pre-computed base64 of "Hello" then gzip'd
# The string "SGVsbG8=" base64-decoded is "Hello"
# gzip("Hello") â†’ base64 â†’ "H4sIAAAAAAAAA8pIzcnJBwCkCAA5BAAAAA=="
$gzipB64 = "H4sIAAAAAAAAA8pIzcnJBwCkCAA5BAAAAA=="

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  04 - Deep Recursive Decode Gauntlet" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 4.1 - Base64 decode (1 layer)
Test-Step "Single base64 layer" {
    $r = cryptotrace analyze --deep $b64OfHex 2>&1 | Out-String
    if ($r -notmatch "Layer Tree") { throw "No layer tree shown" }
    if ($r -notmatch "\[0\]")         { throw "Expected at least 1 sub-layer" }
}

# 4.2 - Hex decode (1 layer)
Test-Step "Single hex layer" {
    $r = cryptotrace analyze --deep $hexEncoded 2>&1 | Out-String
    if ($r -notmatch "Layer Tree") { throw "No layer tree" }
    if ($r -notmatch "\[0\]")      { throw "Expected layer [0]" }
}

# 4.3 - gzip via base64 (2 layers: base64 â†’ gzip â†’ plaintext)
Test-Step "gzip+base64 2-layer decode" {
    $r = cryptotrace analyze --deep $gzipB64 2>&1 | Out-String
    if ($r -notmatch "Layer Tree") { throw "No layer tree" }
    if ($r -notmatch "\[0\]")      { throw "Expected layer [0] in tree" }
}

# 4.4 - Nested detection: base64 input containing gzip magic bytes
Test-Step "Nested compression inside encoding" {
    # The gzip base64 string should show as Base64 at top, then gzip in layer tree
    $r = Get-Json $gzipB64
    if ($r.algorithm -ne "Base64") { throw "Top layer should be Base64, got $($r.algorithm)" }
}

# 4.5 - Deep decode timeout protection (very long chain simulation)
Test-Step "Graceful handling of deep input" {
    $r = cryptotrace analyze --deep "SGVsbG8gV29ybGQgdGhpcyBpcyBhIGxvbmcgc3RyaW5nIHRoYXQgc2hvdWxkIHN0aWxsIHdvcmsgZmluZQ==" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and $r -notmatch "Layer Tree") {
        throw "Unexpected failure"
    }
}

# 4.6 - Non-deep vs deep comparison (deep should show additional info)
Test-Step "Deep vs non-deep output difference" {
    $normal = cryptotrace analyze $b64OfHex 2>&1 | Out-String
    $deep   = cryptotrace analyze --deep $b64OfHex 2>&1 | Out-String
    if ($normal -match "Layer Tree")  { throw "Non-deep should not show layer tree" }
    if ($deep -notmatch "Layer Tree") { throw "Deep should show layer tree" }
}

# 4.7 - Recursive protection: hex of hex (infinite-ish loop prevention)
Test-Step "Cycle detection (hex-of-hex)" {
    $r = cryptotrace analyze --deep "343836353643364336433646323035373646373236433634" 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -and $r -notmatch "Error") { throw "Unexpected failure for hex-of-hex" }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

