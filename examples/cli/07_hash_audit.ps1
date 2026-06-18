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

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  07 - Weak Hash CVE Audit" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 7.1 - MD5: Critical risk, collision CVEs
Test-Step "MD5 â†’ Critical + CVEs" {
    $r = Get-Json "5d41402abc4b2a76b9719d911017c592"
    if ($r.algorithm -ne "MD5")          { throw "Expected MD5" }
    if ($r.risk_level -ne "Critical")     { throw "Expected Critical" }
    if ($r.confidence -lt 0.90)           { throw "Confidence too low" }
    $raw = cryptotrace analyze --explain "5d41402abc4b2a76b9719d911017c592" 2>&1 | Out-String
    if ($raw -notmatch "collision_vulnerable") { throw "Expected collision warning" }
}

# 7.2 - SHA1: High risk, collision CVEs
Test-Step "SHA1 â†’ High + collision CVEs" {
    $r = Get-Json "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
    if ($r.algorithm -ne "SHA1")  { throw "Expected SHA1, got $($r.algorithm)" }
    if ($r.risk_level -ne "High") { throw "Expected High risk, got $($r.risk_level)" }
}

# 7.3 - SHA256: Low risk, no CVEs
Test-Step "SHA256 â†’ Low risk, no weaknesses" {
    $r = Get-Json "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    if ($r.algorithm -ne "SHA256") { throw "Expected SHA256, got $($r.algorithm)" }
    if ($r.risk_level -ne "Low")   { throw "Expected Low risk, got $($r.risk_level)" }
    if ($r.weakness -and $r.weakness.Length -gt 0) { throw "SHA256 should have no weaknesses" }
}

# 7.4 - NTLM: Critical risk
Test-Step "NTLM â†’ Critical" {
    $r = Get-Json "209C6174DA490CAEB422F3FA5A7AE634"
    if ($r.algorithm -ne "NTLM")  { throw "Expected NTLM, got $($r.algorithm)" }
    if ($r.risk_level -ne "Critical") { throw "Expected Critical, got $($r.risk_level)" }
}

# 7.5 - bcrypt (cost â‰¥ 12): Low risk
Test-Step "bcrypt cost>=12 â†’ Low risk" {
    $r = Get-Json '$2a$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Q4p0F0n0Z0v0y0W0'
    if ($r.algorithm -notmatch "bcrypt") { throw "Expected bcrypt" }
    if ($r.risk_level -eq "Critical")    { throw "bcrypt with cost>=12 should not be Critical" }
}

# 7.6 - SHA512: Low risk
Test-Step "SHA512 â†’ Low risk" {
    $r = Get-Json "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    if ($r.algorithm -ne "SHA512") { throw "Expected SHA512" }
    if ($r.risk_level -ne "Low")   { throw "Expected Low risk" }
}

# 7.7 - Explain mode shows CVEs for weak algorithms
Test-Step "Explain CVEs for MD5" {
    $raw = cryptotrace analyze --explain "5d41402abc4b2a76b9719d911017c592" 2>&1 | Out-String
    if ($raw -notmatch "CVE-")  { throw "No CVEs in explain output" }
    if ($raw -notmatch "MD5")   { throw "MD5 not mentioned in explain" }
}

# 7.8 - Explain mode shows no CVEs for strong algorithms
Test-Step "No CVEs for SHA256 explain" {
    $raw = cryptotrace analyze --explain "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" 2>&1 | Out-String
    if ($raw -match "CVE-20[0-9][0-9]-") { throw "SHA256 should not show CVEs" }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

