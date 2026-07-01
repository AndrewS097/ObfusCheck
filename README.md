# ObfusCheck

ObfusCheck is a simple PowerShell tool that scans script files for signs of obfuscation and suspicious patterns.

The tool is designed for basic defensive review, malware triage, and learning. It only reads the file being scanned and does not execute it.

## Features

* Scans script files for suspicious patterns
* Detects encoded PowerShell commands
* Detects Base64-looking strings
* Flags web download commands
* Flags hidden execution options
* Flags suspicious Windows utilities
* Prints findings in the terminal
* Saves findings to a CSV report

## What It Detects

ObfusCheck looks for patterns such as:

* `-EncodedCommand`
* `FromBase64String`
* `Invoke-Expression`
* `Invoke-WebRequest`
* `DownloadString`
* `ExecutionPolicy Bypass`
* `-WindowStyle Hidden`
* `certutil`
* `bitsadmin`
* `mshta`
* `rundll32`
* `regsvr32`
* Long Base64-looking strings
* Very long lines
* Heavy string concatenation
* Many backticks

## Requirements

* Windows
* PowerShell
* Git
* A script file to scan

## How to Run

### 1. Open PowerShell

Open **Windows PowerShell** or **Windows Terminal**.

### 2. Clone the GitHub repository

```powershell
git clone https://github.com/AndrewS097/ObfusCheck.git
```

### 3. Go into the project folder

```powershell
cd ObfusCheck
```

### 4. Run ObfusCheck

```powershell
powershell -ExecutionPolicy Bypass -File .\ObfusCheck.ps1
```

### 5. Enter the file to scan

When prompted, enter the script file name or path.

Example:

```text
example_script.ps1
```

You can also enter a full file path:

```text
C:\Path\To\Your\File.ps1
```

## Example Workflow

```powershell
git clone https://github.com/AndrewS097/ObfusCheck.git
cd ObfusCheck
powershell -ExecutionPolicy Bypass -File .\ObfusCheck.ps1
```

Then enter the file you want to scan when prompted.

## Output

If suspicious patterns are found, the tool prints the finding in the terminal.

Example:

```text
Possible Obfuscation Found
Line: 1
Reason: Invoke-Expression execution
Code:
Invoke-Expression "example"
```

The tool also saves findings to:

```text
obfuscheck_report.csv
```

## Notes

ObfusCheck does not prove that a script is malicious. It only identifies suspicious patterns that may need further review.

This tool is intended for learning, demonstrations, and basic defensive security analysis.
