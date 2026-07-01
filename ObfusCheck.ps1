# ==================================================
# ObfusCheck
# Simple Script Obfuscation Detector
# ==================================================
# Purpose:
# This tool scans a script file for signs of obfuscation.
# It is meant for defensive review and basic malware triage.
#
# It checks for:
# - Encoded PowerShell commands
# - Base64-looking text
# - Invoke-Expression usage
# - Download commands
# - Long suspicious lines
# - String concatenation
# - Backtick obfuscation
# - Hidden execution flags
#
# The tool only reads the file. It does not run it.
# ==================================================

Write-Host "Starting ObfusCheck..." -ForegroundColor Cyan
Write-Host "Type Q to quit."
Write-Host ""

# Ask the user for a file to scan
$filePath = Read-Host "Enter the script file to scan"

# Graceful exit
if ($filePath -eq "Q" -or $filePath -eq "q") {
    Write-Host "Exiting ObfusCheck. Goodbye!" -ForegroundColor Green
    exit
}

# Check if the file exists
if (-not (Test-Path $filePath)) {
    Write-Host "File not found: $filePath" -ForegroundColor Red
    exit
}

# CSV report file
$reportFile = "obfuscheck_report.csv"

# Suspicious patterns to look for
$patterns = @(
    @{
        Reason = "Encoded PowerShell command"
        Pattern = "(?i)-EncodedCommand|-enc"
    },
    @{
        Reason = "Base64 decoding"
        Pattern = "(?i)FromBase64String"
    },
    @{
        Reason = "Invoke-Expression execution"
        Pattern = "(?i)\bIEX\b|Invoke-Expression"
    },
    @{
        Reason = "Web download command"
        Pattern = "(?i)Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString|DownloadFile|WebClient"
    },
    @{
        Reason = "Execution policy bypass"
        Pattern = "(?i)ExecutionPolicy\s+Bypass"
    },
    @{
        Reason = "Hidden PowerShell window"
        Pattern = "(?i)-WindowStyle\s+Hidden|-w\s+hidden"
    },
    @{
        Reason = "NoProfile or NoLogo flag"
        Pattern = "(?i)-NoProfile|-nop|-NoLogo"
    },
    @{
        Reason = "Defender tampering keyword"
        Pattern = "(?i)Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath"
    },
    @{
        Reason = "Suspicious Windows utility"
        Pattern = "(?i)certutil|bitsadmin|mshta|rundll32|regsvr32"
    },
    @{
        Reason = "Character-based obfuscation"
        Pattern = "(?i)\[char\]|Chr\("
    }
)

# Store findings here
$results = @()

# Read the file line by line
$lines = Get-Content $filePath

# Scan each line
for ($i = 0; $i -lt $lines.Count; $i++) {

    $lineNumber = $i + 1
    $line = $lines[$i]
    $reasons = @()

    # Check normal suspicious patterns
    foreach ($item in $patterns) {
        if ($line -match $item.Pattern) {
            $reasons += $item.Reason
        }
    }

    # Check for long Base64-looking strings
    if ($line -match "[A-Za-z0-9+/]{80,}={0,2}") {
        $reasons += "Long Base64-looking string"
    }

    # Check for very long lines
    if ($line.Length -gt 300) {
        $reasons += "Very long line"
    }

    # Check for heavy string concatenation
    if (($line -split "\+").Count -gt 8) {
        $reasons += "Heavy string concatenation"
    }

    # Check for many PowerShell backticks
    $backtickCount = ($line.ToCharArray() | Where-Object { $_ -eq [char]0x60 }).Count

    if ($backtickCount -gt 5) {
        $reasons += "Many backticks"
    }

    # If anything suspicious was found, print it
    if ($reasons.Count -gt 0) {

        Write-Host "----------------------------------------" -ForegroundColor DarkGray
        Write-Host "Possible Obfuscation Found" -ForegroundColor Yellow
        Write-Host "Line: $lineNumber"
        Write-Host "Reason: $($reasons -join ', ')"
        Write-Host "Code:" -ForegroundColor Cyan
        Write-Host $line
        Write-Host ""

        # Save finding
        $results += [PSCustomObject]@{
            Time       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            File       = $filePath
            LineNumber = $lineNumber
            Reason     = ($reasons -join ", ")
            Code       = $line
        }
    }
}

# Final summary
if ($results.Count -eq 0) {
    Write-Host "No obvious obfuscation found." -ForegroundColor Green
} else {
    Write-Host "Scan complete. Findings found: $($results.Count)" -ForegroundColor Yellow

    # Save results to CSV
    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "Report saved to: $reportFile" -ForegroundColor Cyan
}