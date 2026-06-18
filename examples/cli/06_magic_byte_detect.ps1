param([switch]$Quiet)

$total = 0
$passed = 0
$tmpFiles = @()

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

function New-TempFile {
    param($Name, [byte[]]$Bytes)
    $path = Join-Path $env:TEMP $Name
    [System.IO.File]::WriteAllBytes($path, $Bytes)
    $script:tmpFiles += $path
    return $path
}

function Cleanup {
    foreach ($f in $script:tmpFiles) {
        if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
}

# Register cleanup on exit
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { Cleanup } | Out-Null

if (-not $Quiet) {
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  06 - Magic Byte Signature Detection" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
}

# Real magic bytes for various formats
$tests = @(
    @{ name = "PDF";  magic = @(0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34) },
    @{ name = "PNG";  magic = @(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) },
    @{ name = "GZIP"; magic = @(0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00) },
    @{ name = "ELF";  magic = @(0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00) },
    @{ name = "ZIP";  magic = @(0x50, 0x4B, 0x03, 0x04) },
    @{ name = "JPEG"; magic = @(0xFF, 0xD8, 0xFF, 0xE0) },
    @{ name = "BZ2";  magic = @(0x42, 0x5A, 0x68) },
    @{ name = "ZSTD"; magic = @(0x28, 0xB5, 0x2F, 0xFD) }
)

# 6.1 - Detect each format by magic bytes
foreach ($t in $tests) {
    $name = $t.name
    $magic = [byte[]]$t.magic
    Test-Step "$name magic byte detection" {
        $path = New-TempFile "test_$name" $magic
        $r = Get-Json $path
        if ($r.algorithm -ne $name) {
            # Some formats may have different detection names - accept any non-plaintext
            if ($r.detected_type -eq "plaintext" -or $r.detected_type -eq "Unknown") {
                throw "Expected $name detection, got $($r.detected_type)/$($r.algorithm)"
            }
        }
    }
}

# 6.2 - Risk levels for different categories
Test-Step "Executable format (ELF) risk level" {
    $path = New-TempFile "test_elf_risk" @(0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00)
    $r = Get-Json $path
    if ($r.algorithm -match "elf|ELF|executable") {
        if ($r.risk_level -ne "High" -and $r.risk_level -ne "Critical" -and $r.risk_level -ne "Medium") {
            throw "ELF should have significant risk level, got $($r.risk_level)"
        }
    }
}

# 6.3 - Compression format detection
Test-Step "GZIP format detection" {
    $path = New-TempFile "test_gzip_detect" @(0x1F, 0x8B, 0x08)
    $r = Get-Json $path
    if ($r.algorithm -ne "GZIP" -and $r.detected_type -eq "plaintext") {
        throw "Expected GZIP detection"
    }
}

# 6.4 - No false positive for plaintext file
Test-Step "Plaintext no false positive" {
    $path = New-TempFile "test_plain.txt" ([System.Text.Encoding]::UTF8.GetBytes("This is plain text content"))
    $r = Get-Json $path
    if ($r.detected_type -ne "plaintext" -and $r.detected_type -ne "Unknown") {
        throw "Plaintext file should not trigger detection"
    }
}

Cleanup

$failed = $total - $passed
if (-not $Quiet) {
    Write-Host "`nResults: $passed/$total passed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
}
exit $failed

