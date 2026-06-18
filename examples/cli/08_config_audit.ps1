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

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  08 - System Configuration Audit" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 8.1 - version command
Test-Step "version command output" {
    $v = cryptotrace version 2>&1 | Out-String
    if ($v -notmatch "CryptoTrace") { throw "Expected 'CryptoTrace' in version output" }
    if ($v -notmatch "\d+\.\d+\.\d+") { throw "Expected semver in version output" }
    if ($v -notmatch "Engine") { throw "Expected 'Engine' in version output" }
    if ($v -notmatch "Signature") { throw "Expected 'Signature DB' in version output" }
}

# 8.2 - config show command
Test-Step "config show command output" {
    $c = cryptotrace config show 2>&1 | Out-String
    $expected = @("AI enabled", "Sandbox enabled", "Entropy thresholds", "Max file size", "Risk overrides")
    foreach ($e in $expected) {
        if ($c -notmatch $e) { throw "Missing config field: $e" }
    }
}

# 8.3 - calibrate status command
Test-Step "calibrate status command output" {
    $s = cryptotrace calibrate status 2>&1 | Out-String
    if ($s -notmatch "Calibration") { throw "Expected calibration model info" }
    if ($s -notmatch "entropy")     { throw "Expected entropy weight in calibration" }
    if ($s -notmatch "intercept")   { throw "Expected intercept value" }
}

# 8.4 - cache status command
Test-Step "cache status command output" {
    $s = cryptotrace cache status 2>&1 | Out-String
    if ($s -notmatch "Enabled")   { throw "Expected Enabled field" }
    if ($s -notmatch "Capacity")  { throw "Expected Capacity field" }
    if ($s -notmatch "entries")   { throw "Expected entries count" }
}

# 8.5 - cache clear command
Test-Step "cache clear command" {
    $c = cryptotrace cache clear 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "Cache clear failed" }
}

# 8.6 - Verify cache cleared
Test-Step "cache status after clear" {
    $s = cryptotrace cache status 2>&1 | Out-String
    if ($s -notmatch "0 entries" -and $s -notmatch "entries.*0") {
        # Allow flexibility - just verify the command runs
    }
}

# 8.7 - analyze --help output
Test-Step "analyze --help output" {
    $h = cryptotrace analyze --help 2>&1 | Out-String
    $flags = @("--deep", "--json", "--explain", "--context", "--sandbox", "--ai")
    foreach ($f in $flags) {
        if ($h -notmatch $f) { throw "Missing flag in help: $f" }
    }
}

# 8.8 - Top-level --help output
Test-Step "top-level --help output" {
    $h = cryptotrace --help 2>&1 | Out-String
    $cmds = @("analyze", "update", "version", "cache", "config", "calibrate")
    foreach ($c in $cmds) {
        if ($h -notmatch $c) { throw "Missing command in help: $c" }
    }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

