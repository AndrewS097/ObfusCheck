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
# - Excessive dollar signs
# - Hidden execution flags
#
# The tool only reads the file. It does not run it.
#
# If Windows blocks the script, run it with:
# powershell.exe -ExecutionPolicy Bypass -File .\ObfusCheck.ps1
# This only bypasses the policy for the current command.
# ==================================================

Write-Host "Starting ObfusCheck..." -ForegroundColor Cyan
Write-Host "Type Q to quit."
Write-Host ""

# Ask the user for a file to scan
$filePath = (Read-Host "Enter the script file to scan").Trim()

# Graceful exit
if ($filePath -eq "Q" -or $filePath -eq "q") {
    Write-Host "Exiting ObfusCheck. Goodbye!" -ForegroundColor Green
    exit
}

# Remove quotation marks from copied file paths
$filePath = $filePath.Trim('"')

# Check if the file exists and is a file
if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
    Write-Host "File not found: $filePath" -ForegroundColor Red
    exit
}

# Get the full file path
$filePath = (Resolve-Path -LiteralPath $filePath).Path

# CSV report files
$reportFile = "obfuscheck_report.csv"
$historyFile = "obfuscheck_scan_history.csv"

# Suspicious patterns to look for
$patterns = @(
    @{
        Reason = "Encoded PowerShell command"
        Pattern = "(?i)(?:-EncodedCommand\b|-enc\b)"
    },
    @{
        Reason = "Base64 decoding"
        Pattern = "(?i)\bFromBase64String\b"
    },
    @{
        Reason = "Invoke-Expression execution"
        Pattern = "(?i)\b(?:IEX|Invoke-Expression)\b"
    },
    @{
        Reason = "Web download command"
        Pattern = "(?i)\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString|DownloadFile|WebClient)\b"
    },
    @{
        Reason = "Execution policy bypass"
        Pattern = "(?i)ExecutionPolicy\s+Bypass\b"
    },
    @{
        Reason = "Hidden PowerShell window"
        Pattern = "(?i)(?:-WindowStyle\s+Hidden\b|-w\s+hidden\b)"
    },
    @{
        Reason = "NoProfile or NoLogo flag"
        Pattern = "(?i)(?:-NoProfile\b|-nop\b|-NoLogo\b)"
    },
    @{
        Reason = "Defender tampering keyword"
        Pattern = "(?i)\b(?:Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath)\b"
    },
    @{
        Reason = "Suspicious Windows utility"
        Pattern = "(?i)\b(?:certutil|bitsadmin|mshta|rundll32|regsvr32)\b"
    },
    @{
        Reason = "Character-based obfuscation"
        Pattern = "(?i)(?:\[char\]|Chr\()"
    }
)

# Store findings here
$results = @()

# Read the file line by line
try {
    $lines = @(Get-Content -LiteralPath $filePath -ErrorAction Stop)
}
catch {
    Write-Host "Unable to read the file: $($_.Exception.Message)" -ForegroundColor Red
    exit
}

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
    $backtickCount = (
        $line.ToCharArray() |
        Where-Object { $_ -eq [char]0x60 }
    ).Count

    if ($backtickCount -gt 5) {
        $reasons += "Many backticks"
    }

    # Check for excessive dollar signs
    $dollarSignCount = ([regex]::Matches($line, '\$')).Count

    if ($dollarSignCount -gt 10) {
        $reasons += "Excessive dollar signs"
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

# Set scan status
if ($results.Count -eq 0) {
    $scanStatus = "Clean"
}
else {
    $scanStatus = "Possible Obfuscation Found"
}

# Record every scanned file, including clean files
$historyEntry = [PSCustomObject]@{
    Time     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    File     = $filePath
    Status   = $scanStatus
    Findings = $results.Count
}

# Append the scan to the history file
if (Test-Path -LiteralPath $historyFile) {
    $historyEntry |
        Export-Csv -Path $historyFile -NoTypeInformation -Append
}
else {
    $historyEntry |
        Export-Csv -Path $historyFile -NoTypeInformation
}

# Final summary
if ($results.Count -eq 0) {
    Write-Host "No obvious obfuscation found." -ForegroundColor Green
}
else {
    Write-Host "Scan complete. Findings found: $($results.Count)" -ForegroundColor Yellow

    # Save results to CSV
    $results |
        Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "Report saved to: $reportFile" -ForegroundColor Cyan
}

Write-Host "Scan history saved to: $historyFile" -ForegroundColor Cyan
