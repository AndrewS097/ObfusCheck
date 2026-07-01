# This file is safe.
# It only prints suspicious keywords for testing ObfusCheck.

Write-Host "Invoke-Expression test"
Write-Host "-EncodedCommand test"
Write-Host "FromBase64String test"
Write-Host "DownloadString test"
Write-Host "ExecutionPolicy Bypass test"
Write-Host "certutil test"
Write-Host "mshta test"
Write-Host "rundll32 test"
Write-Host "regsvr32 test"

# Long fake Base64-looking string for testing
Write-Host "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWg=="