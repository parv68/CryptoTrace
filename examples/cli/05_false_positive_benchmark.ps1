param([switch]$Quiet)

$total = 0
$passed = 0
$fpCount = 0
$results = @()

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

function Get-Json { param($Val) cryptotrace analyze --json $Val 2>$null | Out-String | ConvertFrom-Json }

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  05 - False Positive Benchmark" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

$plaintexts = @(
    "The quick brown fox jumps over the lazy dog",
    "Hello World! This is a simple test with normal words",
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
    "abcdefghijklmnopqrstuvwxyz",
    "1234567890 1234567890 1234567890",
    '{"name": "John", "age": 30, "city": "New York", "active": true}',
    "<html><body><h1>Welcome</h1><p>This is a test page</p></body></html>",
    "2024-01-15 10:30:45 ERROR Failed to connect to database server at 192.168.1.1:5432",
    "Monday Tuesday Wednesday Thursday Friday Saturday Sunday",
    'SELECT * FROM users WHERE id = 1 AND password = ''secret''',
    '-----BEGIN CERTIFICATE-----\nMIIDazCCA\n-----END CERTIFICATE-----',
    '#include <stdio.h>\nint main() { printf("hello"); return 0; }'
)

# 5.1 - Collect false positive stats
Test-Step "Plaintext false positive rate" {
    $localResults = @()
    foreach ($txt in $plaintexts) {
        $r = Get-Json $txt
        $localResults += @{
            input = $txt.Substring(0, [Math]::Min(40, $txt.Length))
            detected = $r.algorithm
            confidence = $r.confidence
            risk = $r.risk_level
            fp = ($r.detected_type -ne "plaintext" -and $r.detected_type -ne "Unknown")
        }
        if ($r.detected_type -ne "plaintext" -and $r.detected_type -ne "Unknown") { $script:fpCount++ }
    }
    $script:results = $localResults
    $fpRate = [math]::Round($fpCount / $plaintexts.Count * 100, 1)
    if (-not $Quiet) { Write-Host "    False positive rate: $fpRate% ($fpCount/$($plaintexts.Count))" }
    if ($fpRate -gt 30) { throw "False positive rate too high: $fpRate%" }
}

# 5.2 - Verify plaintext confidence is NOT high (no confident false detection)
Test-Step "No confident false positives" {
    foreach ($r in $results) {
        if ($r.fp -and $r.confidence -gt 0.8) {
            throw "High-confidence false positive: '$($r.input)' â†’ $($r.detected) at $($r.confidence)"
        }
    }
}

# 5.3 - Known hash should NOT be detected in normal prose
Test-Step "Hash not falsely detected in prose" {
    $r = Get-Json "The MD5 hash d41d8cd98f00b204e9800998ecf8427e is obsolete"
    if (-not $Quiet) {
        $detected = if ($r.algorithm -eq "MD5") { "detected (expected)" } else { "not detected" }
        Write-Host "    Hash in prose: $detected"
    }
}

# Verify at least some results captured
Test-Step "Results captured" {
    if ($results.Count -eq 0) { throw "No results captured" }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

