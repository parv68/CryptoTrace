param([switch]$Quiet)

$total = 0
$passed = 0

function Test-Step {
    param($Name, $Script)
    $script:total++
    try {
        $result = & $Script
        if (-not $Quiet) { Write-Host "  PASS: $Name" -ForegroundColor Green }
        $script:passed++
    } catch {
        if (-not $Quiet) { Write-Host "  FAIL: $Name`n    $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Get-Json { param($Val) cryptotrace analyze --json $Val 2>&1 | Out-String | ConvertFrom-Json }

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
$hash = "5d41402abc4b2a76b9719d911017c592"
$b64  = "SGVsbG8gV29ybGQ="
$hex  = "48656C6C6F"
$deep = "NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0"

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  01 - Attack Chain Reconstruction" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 1.1 - MD5 hash detection and risk level
Test-Step "MD5 hash detection" {
    $r = Get-Json $hash
    if ($r.algorithm -ne "MD5")   { throw "Expected MD5, got $($r.algorithm)" }
    if ($r.detected_type -ne "hash") { throw "Expected type=hash, got $($r.detected_type)" }
    if ($r.risk_level -ne "Critical") { throw "Expected risk=Critical, got $($r.risk_level)" }
    if ($r.confidence -lt 0.90)   { throw "Confidence too low: $($r.confidence)" }
}

# 1.2 - CVE mapping with --explain
Test-Step "CVE mapping presence" {
    $raw = cryptotrace analyze --explain $hash 2>&1 | Out-String
    if ($raw -notmatch "CVE-") { throw "No CVEs found in explain output" }
    if ($raw -notmatch "collision_vulnerable") { throw "Expected collision_vulnerable weakness" }
}

# 1.3 - Base64 encoding detection
Test-Step "Base64 encoding detection" {
    $r = Get-Json $b64
    if ($r.algorithm -ne "Base64") { throw "Expected Base64, got $($r.algorithm)" }
    if ($r.detected_type -ne "encoding") { throw "Expected type=encoding" }
}

# 1.4 - Hex encoding detection
Test-Step "Hex encoding detection" {
    $r = Get-Json $hex
    if ($r.algorithm -ne "Hex") { throw "Expected Hex, got $($r.algorithm)" }
}

# 1.5 - Deep recursive decode layer validation
Test-Step "Recursive decode layer count" {
    $r = cryptotrace analyze --deep $deep 2>&1 | Out-String
    if ($r -notmatch "Layer Tree") { throw "No layer tree in deep output" }
    if ($r -notmatch "\[0\]")     { throw "Expected layer tree with layer 0" }
}

# 1.6 - Sandbox functional equivalence
Test-Step "Sandbox produces same result" {
    $r1 = Get-Json $hash
    $r2 = cryptotrace analyze --sandbox --json $hash 2>&1 | Out-String | ConvertFrom-Json
    if ($r1.algorithm -ne $r2.algorithm) { throw "Algorithm mismatch: $($r1.algorithm) vs $($r2.algorithm)" }
    if ($r1.risk_level -ne $r2.risk_level) { throw "Risk level mismatch" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

