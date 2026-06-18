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

function Get-JsonCtx { param($Val, $Ctx) cryptotrace analyze --json --context $Ctx $Val 2>&1 | Out-String | ConvertFrom-Json }

$hash = "5d41402abc4b2a76b9719d911017c592"
$b64  = "SGVsbG8gV29ybGQ="
$pass = "My secret password is hunter2 but do not tell anyone"

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  03 - Cross-Context Threat Profiling" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 3.1 - Forensics context
Test-Step "Forensics context detection" {
    $r = Get-JsonCtx $hash "forensics"
    if ($r.detection_context -ne "Forensics") { throw "Expected Forensics context, got $($r.detection_context)" }
    if ($r.algorithm -ne "MD5") { throw "Expected MD5, got $($r.algorithm)" }
    if ($r.risk_level -ne "Critical") { throw "Expected Critical risk" }
}

# 3.2 - Malware context
Test-Step "Malware context detection" {
    $r = Get-JsonCtx $hash "malware"
    if ($r.detection_context -ne "Malware") { throw "Expected Malware context, got $($r.detection_context)" }
    if ($r.algorithm -ne "MD5") { throw "Expected MD5" }
    if ($r.risk_level -ne "Critical") { throw "Expected Critical risk" }
}

# 3.3 - Password context
Test-Step "Password context detection" {
    $r = Get-JsonCtx $hash "password"
    if ($r.detection_context -ne "Password") { throw "Expected Password context, got $($r.detection_context)" }
    if ($r.algorithm -ne "MD5") { throw "Expected MD5" }
}

# 3.4 - All three contexts return identical detection fields (only context differs)
Test-Step "Detection consistency across contexts" {
    $rf = Get-JsonCtx $hash "forensics"
    $rm = Get-JsonCtx $hash "malware"
    $rp = Get-JsonCtx $hash "password"
    $fields = @("algorithm", "detected_type", "risk_level")
    foreach ($f in $fields) {
        if ($rf.$f -ne $rm.$f -or $rm.$f -ne $rp.$f) { throw "Field '$f' differs across contexts: '$($rf.$f)' vs '$($rm.$f)' vs '$($rp.$f)'" }
    }
    # Numeric fields may differ in last decimal place; compare with tolerance
    $eps = 1e-12
    foreach ($f in @("entropy", "confidence")) {
        if ([Math]::Abs($rf.$f - $rm.$f) -gt $eps -or [Math]::Abs($rm.$f - $rp.$f) -gt $eps) {
            throw "Field '$f' differs across contexts: $($rf.$f) vs $($rm.$f) vs $($rp.$f)"
        }
    }
}

# 3.5 - Password context with actual password input
Test-Step "Password context + password input" {
    $r = Get-JsonCtx $pass "password"
    if ($r.detection_context -ne "Password") { throw "Expected Password context" }
    if ($r.detected_type -ne "plaintext") { throw "Expected plaintext for random password" }
}

# 3.6 - JSON structural completeness
Test-Step "JSON structural completeness" {
    $r = Get-JsonCtx $hash "forensics"
    $required = @("input_hash", "entropy", "detected_type", "algorithm", "confidence",
                  "risk_level", "signals", "detection_context", "engine_version")
    foreach ($f in $required) {
        if ($null -eq $r.$f) { throw "Missing required field: $f" }
    }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

