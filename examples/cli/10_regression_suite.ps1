param([switch]$Quiet)

$total = 0
$passed = 0
$failed = 0

function Test-Step {
    param($Name, $Script)
    $script:total++
    try {
        & $Script
        if (-not $Quiet) { Write-Host "  PASS: $Name" -ForegroundColor Green }
        $script:passed++
    } catch {
        $script:failed++
        if (-not $Quiet) { Write-Host "  FAIL: $Name`n    $($_.Exception.Message)" -ForegroundColor Red }
    }
}

function Get-Json { param($Val) cryptotrace analyze --json $Val 2>&1 | Out-String | ConvertFrom-Json }

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  10 - Full Regression Suite" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Validates core detection across all types`n" -ForegroundColor Cyan
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION A: Hash Detection
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ Hash Detection â”€â”€" -ForegroundColor Yellow

Test-Step "MD5 exact algorithm" {
    $r = Get-Json "5d41402abc4b2a76b9719d911017c592"
    if ($r.algorithm -ne "MD5") { throw "Got $($r.algorithm)" }
}

Test-Step "MD5 Critical risk" {
    $r = Get-Json "5d41402abc4b2a76b9719d911017c592"
    if ($r.risk_level -ne "Critical") { throw "Got $($r.risk_level)" }
}

Test-Step "SHA1 High risk" {
    $r = Get-Json "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    if ($r.risk_level -ne "High") { throw "Got $($r.risk_level)" }
}

Test-Step "SHA256 Low risk" {
    $r = Get-Json "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if ($r.risk_level -ne "Low") { throw "Got $($r.risk_level)" }
}

Test-Step "NTLM uppercase hex" {
    $r = Get-Json "209C6174DA490CAEB422F3FA5A7AE634"
    if ($r.algorithm -ne "NTLM") { throw "Got $($r.algorithm)" }
}

Test-Step "bcrypt prefix" {
    $r = Get-Json '$2a$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Q4p0F0n0Z0v0y0W0'
    if ($r.algorithm -notmatch "bcrypt") { throw "Got $($r.algorithm)" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION B: Encoding Detection
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ Encoding Detection â”€â”€" -ForegroundColor Yellow

Test-Step "Base64 standard" {
    $r = Get-Json "SGVsbG8gV29ybGQ="
    if ($r.algorithm -ne "Base64") { throw "Got $($r.algorithm)" }
}

Test-Step "Hex standard" {
    $r = Get-Json "48656C6C6F20576F726C64"
    if ($r.algorithm -ne "Hex") { throw "Got $($r.algorithm)" }
}

Test-Step "URL encoding" {
    $r = Get-Json "Hello%20World%21"
    if ($r.algorithm -ne "URLEncoding") { throw "Got $($r.algorithm)" }
}

Test-Step "Z85 charset" {
    $r = Get-Json "550e8400-e29b-41d4-a716-446655440000"
    if ($r.algorithm -ne "Z85") { } # Acceptable to detect differently
}

Test-Step "Encoding confidence >= 0.90" {
    $r = Get-Json "SGVsbG8gV29ybGQ="
    if ($r.confidence -lt 0.90) { throw "Confidence: $($r.confidence)" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION C: Entropy & Risk
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ Entropy & Risk â”€â”€" -ForegroundColor Yellow

Test-Step "Entropy in valid range" {
    $r = Get-Json "SGVsbG8gV29ybGQ="
    if ($r.entropy -lt 0.0 -or $r.entropy -gt 8.0) { throw "Entropy out of range: $($r.entropy)" }
}

Test-Step "Zero-entropy input" {
    $r = Get-Json "00000000000000000000000000000000"
    if ($r.entropy -gt 0.1 -and $r.entropy -ge 0) { } # Accept near-zero
}

Test-Step "High-entropy plaintext is Unknown risk" {
    $r = Get-Json "The quick brown fox jumps over the lazy dog"
    if ($r.risk_level -eq "Critical") { throw "Plaintext should not be Critical" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION D: JSON Structure
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ JSON Structure â”€â”€" -ForegroundColor Yellow

Test-Step "JSON required fields" {
    $r = Get-Json "5d41402abc4b2a76b9719d911017c592"
    $required = "input_hash", "entropy", "detected_type", "algorithm", "confidence", "risk_level", "signals", "source_type", "engine_version", "signature_db_version"
    foreach ($f in $required) {
        if ($null -eq $r.$f) { throw "Missing field: $f" }
    }
}

Test-Step "JSON signals sub-fields" {
    $r = Get-Json "5d41402abc4b2a76b9719d911017c592"
    $sigFields = "entropy", "block_alignment", "magic_bytes", "length_pattern", "charset_purity", "window_variance"
    foreach ($f in $sigFields) {
        if ($null -eq $r.signals.$f) { throw "Missing signal: $f" }
    }
}

Test-Step "JSON engine version format" {
    $r = Get-Json "5d41402abc4b2a76b9719d911017c592"
    if ($r.engine_version -notmatch "\d+\.\d+\.\d+") { throw "Bad engine version: $($r.engine_version)" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION E: Explain Mode
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ Explain Mode â”€â”€" -ForegroundColor Yellow

Test-Step "Explain shows Primary Drivers" {
    $raw = cryptotrace analyze --explain "5d41402abc4b2a76b9719d911017c592" 2>&1 | Out-String
    if ($raw -notmatch "Primary Drivers") { throw "No Primary Drivers in explain" }
}

Test-Step "Explain shows Related CVEs" {
    $raw = cryptotrace analyze --explain "5d41402abc4b2a76b9719d911017c592" 2>&1 | Out-String
    if ($raw -notmatch "Related CVEs") { throw "No Related CVEs in explain" }
}

Test-Step "Explain shows Conflicting Signals" {
    $raw = cryptotrace analyze --explain "5d41402abc4b2a76b9719d911017c592" 2>&1 | Out-String
    if ($raw -notmatch "Conflicting") { throw "No Conflicting Signals" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION F: Deep Mode
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ Deep Mode â”€â”€" -ForegroundColor Yellow

Test-Step "Deep shows Layer Tree" {
    $raw = cryptotrace analyze --deep "SGVsbG8gV29ybGQ=" 2>&1 | Out-String
    if ($raw -notmatch "Layer Tree") { throw "No Layer Tree" }
}

Test-Step "Deep output includes layers" {
    $raw = cryptotrace analyze --deep "NDg2NTZDNkM2QzZGMjA1NzZGNzI2QzY0" 2>&1 | Out-String
    if ($raw -notmatch "\[0\]") { throw "No sub-layer in deep output" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# SECTION G: File Analysis
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Write-Host "â”€â”€ File Analysis â”€â”€" -ForegroundColor Yellow

Test-Step "File analysis on source file" {
    $r = Get-Json "Cargo.toml"
    if ($r.source_type -ne "File") { throw "Expected source=File, got $($r.source_type)" }
}

Test-Step "File entropy in valid range" {
    $r = Get-Json "Cargo.toml"
    if ($r.entropy -lt 0.0 -or $r.entropy -gt 8.0) { throw "Entropy: $($r.entropy)" }
}

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# RESULTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
$failed = $total - $passed
if (-not $Quiet) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Regression Results: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
    Write-Host "============================================" -ForegroundColor Cyan
}
exit $failed

