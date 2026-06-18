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
    Write-Host "  02 - Adversarial Evasion Detection" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 2.1 - Zero-entropy input (all zeros, 32 hex chars)
Test-Step "Zero-entropy MD5" {
    $r = Get-Json "00000000000000000000000000000000"
    if ($r.algorithm -ne "MD5") { throw "Expected MD5, got $($r.algorithm)" }
    if ($r.entropy -gt 0.1) { throw "Expected near-zero entropy, got $($r.entropy)" }
}

# 2.2 - Deliberately padded base64 with extra = signs
Test-Step "Over-padded base64" {
    $r = Get-Json "SGVsbG8gV29ybGQ===="
    # Extra = signs shift detection; verify it's still an encoding
    if ($r.detected_type -ne "encoding") { throw "Expected encoding type, got $($r.detected_type)" }
}

# 2.3 - String that could be hex OR base64 (ambiguous)
Test-Step "Ambiguous hex/base64 string" {
    $r = Get-Json "e3b0c44298fc1c149afbf4c8996fb927ae41e4649b934ca495991b7852b855"
    # Accept Hex or SHA256 - both are valid interpretations
    if ($r.detected_type -ne "encoding" -and $r.detected_type -ne "hash") { throw "Expected encoding or hash, got $($r.detected_type)" }
}

# 2.4 - Mixed encoding with visible plaintext clues
Test-Step "Mixed encoding tokens" {
    $r = Get-Json "The password is abc123! Don't tell anyone."
    if ($r.detected_type -ne "plaintext") { throw "Expected plaintext for English sentence, got $($r.detected_type)" }
    if ($r.confidence -gt 0.5) { throw "Confidence should be low for plaintext" }
}

# 2.5 - Very long alphanumeric (random-looking, not a hash or encoding)
Test-Step "High-entropy random-looking string" {
    $r = Get-Json "ecWUoO0a0Yb1zB2xR3vA4sD5fG6hJ7kL8zX9cV0bN"
    if ($r.entropy -lt 4.0) { throw "Expected high entropy, got $($r.entropy)" }
}

# 2.6 - Plain English with special characters (should be plaintext/low confidence)
Test-Step "Plaintext with special chars" {
    $r = Get-Json "Hello World! This is a test. price=\$49.99 email=user@example.com"
    if ($r.detected_type -ne "plaintext") { throw "Expected plaintext" }
    if ($r.confidence -gt 0.5) { throw "Confidence should be low for plaintext" }
}

# 2.7 - Valid URL encoding
Test-Step "URL-encoded string" {
    $r = Get-Json "Hello%20World%21%20This%20is%20a%20test"
    if ($r.algorithm -ne "URLEncoding") { throw "Expected URLEncoding, got $($r.algorithm)" }
}

# 2.8 - UUID v4 format (should detect as hash/UUID or plaintext, not high risk)
Test-Step "UUID v4 format" {
    $r = Get-Json "550e8400-e29b-41d4-a716-446655440000"
    if ($r.risk_level -eq "Critical") { throw "UUID should not be Critical risk" }
}

# 2.9 - bcrypt hash prefix detection
Test-Step "bcrypt hash prefix" {
    $r = Get-Json '$2a$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Q4p0F0n0Z0v0y0W0'
    if ($r.algorithm -notmatch "bcrypt") { throw "Expected bcrypt, got $($r.algorithm)" }
}

# 2.10 - Missing pad character in base64
Test-Step "Base64 without padding" {
    $r = Get-Json "SGVsbG8gV29ybGQ"
    # Unpadded base64 may be detected as Base58; accept either
    if ($r.algorithm -ne "Base64" -and $r.algorithm -ne "Base58") { throw "Expected Base64/Base58 for unpadded, got $($r.algorithm)" }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

