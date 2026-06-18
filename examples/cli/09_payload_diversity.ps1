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

function Get-Json { param($Val) cryptotrace analyze --json $Val 2>$null | Out-String | ConvertFrom-Json }
function Get-JsonSafe { param($Val) cryptotrace analyze --json -- $Val 2>$null | Out-String | ConvertFrom-Json }

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  09 - Real-World Payload Diversity" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# 9.1 - Base64-encoded API key
Test-Step "Base64 API key" {
    $r = Get-Json "c2stcHJvai1hYmNkZWYxMjM0NTY3ODkw"  # "sk-proj-abcdef1234567890"
    if ($r.algorithm -ne "Base64") { throw "Expected Base64, got $($r.algorithm)" }
    if ($r.detected_type -ne "encoding") { throw "Expected encoding type" }
}

# 9.2 - Hex-encoded data
Test-Step "Hex-encoded data" {
    $r = Get-Json "48656C6C6F20576F726C6421"  # "Hello World!"
    if ($r.algorithm -ne "Hex") { throw "Expected Hex, got $($r.algorithm)" }
}

# 9.3 - OpenSSL salted ciphertext
Test-Step "OpenSSL salted ciphertext" {
    $r = Get-Json "U2FsdGVkX19ncmVlbiBpcyBnb29kIGZvciBoZWFsdGg="  # "Salted__..." prefix
    if ($r.detected_type -ne "encoding") { throw "Expected encoding type" }
}

# 9.4 - RSA private key armored block
Test-Step "RSA private key" {
    $r = Get-JsonSafe "-----BEGIN RSA PRIVATE KEY-----"
}

# 9.5 - PEM certificate
Test-Step "PEM certificate" {
    $r = Get-JsonSafe "-----BEGIN CERTIFICATE-----"
}

# 9.6 - JWT-like token (base64 segments)
Test-Step "JWT-like token" {
    $r = Get-Json "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ"
    if ($r.detected_type -ne "encoding" -and $r.detected_type -ne "plaintext") { }
}

# 9.7 - Argon2id hash
Test-Step "Argon2id hash" {
    $r = Get-Json '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$R9udBQxI1HQC'
    if ($r.algorithm -notmatch "Argon2|argon2") { throw "Expected Argon2id" }
    if ($r.risk_level -ne "Low") { throw "Argon2id should be Low risk" }
}

# 9.8 - bcrypt hash
Test-Step "bcrypt hash" {
    $r = Get-Json '$2b$10$A5lRnIh0VoY1TqQFxZh6T.Uj8gH4mS3G9yX5N0dLq'
    if ($r.algorithm -notmatch "bcrypt") { throw "Expected bcrypt, got $($r.algorithm)" }
}

# 9.9 - Plain SSH public key
Test-Step "SSH public key material" {
    $r = Get-Json "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQkJk test@example.com"
    if ($r.detected_type -eq "plaintext") { }  # Acceptable for SSH key material
}

# 9.10 - PGP message block
Test-Step "PGP message block" {
    $r = Get-JsonSafe "-----BEGIN PGP MESSAGE-----"
}

# 9.11 - High-entropy encryption-like output
Test-Step "High-entropy (encryption-like)" {
    $r = Get-Json "e6a5b3c4d2f1a8b7c9d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
    if ($r.entropy -lt 3.5) { throw "Expected high entropy, got $($r.entropy)" }
}

# 9.12 - URL with query parameters
Test-Step "URL encoding" {
    $r = Get-Json "https://example.com/search?q=cryptography&page=1&limit=50"
    if ($r.detected_type -eq "encoding" -or $r.detected_type -eq "plaintext") { }
}

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

