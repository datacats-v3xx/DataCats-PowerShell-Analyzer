# Test PowerShell Script for DataCats PowerShell Analyzer
# This script is NOT actually malicious, but contains patterns that should trigger detections

# Misleading comments to simulate obfuscation attempts
function Add-MisleadingComments {
    param([string]$Message)
    
    Write-Output "# LEGITIMATE SYSADMIN TASK: $Message"
}

Add-MisleadingComments "Starting system maintenance routine"

# Obfuscated variable names
$s3rv1c3 = "Windows Update"
$t4rg3t = "C:\Windows\System32"
$fl4g = $true

# Character obfuscation example - spells "Hello Security Team"
$obfuscatedGreeting = [char]72 + [char]101 + [char]108 + [char]108 + [char]111 + [char]32 + 
                       [char]83 + [char]101 + [char]99 + [char]117 + [char]114 + [char]105 + 
                       [char]116 + [char]121 + [char]32 + [char]84 + [char]101 + [char]97 + [char]109

# Base64 obfuscation example - encodes "This is a harmless message for testing decoders"
$encodedText = "VGhpcyBpcyBhIGhhcm1sZXNzIG1lc3NhZ2UgZm9yIHRlc3RpbmcgZGVjb2RlcnM="

# Suspicious command pattern
Write-Host "Preparing to perform system operations..."

# Obfuscation with string concatenations and replacements
$c_m_d = "Get" + "-Pro" + "cess"
$r_e_g = ("r" + "e" + "g" + "s" + "v").Replace("s", ".")

# Multi-layer obfuscation
$base64Command = "R2V0LVByb2Nlc3MgfCBTZWxlY3QtT2JqZWN0IE5hbWUsIElELCBQYXRoIHwgT3V0LUZpbGUgQzpcVGVtcFxwcm9jZXNzZXMudHh0"
$deobfuscationCommand = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Command))

# Invoking expressions
Add-MisleadingComments "Performing standard maintenance checks"
if ($fl4g) {
    # Will be flagged as suspicious
    try {
        Invoke-Expression "Get-Service | Where-Object {`$_.Status -eq 'Running'}"
    } catch {
        Write-Error "Failed to execute command"
    }
}

# Invoke-WebRequest detection
Add-MisleadingComments "Checking for resources"
$webCheck = {
    Invoke-WebRequest -Uri "https://example.com/resources.xml" -OutFile "C:\Temp\resource_check.xml"
}

# Registry modification detection
Add-MisleadingComments "Updating configuration settings"
$registryUpdate = {
    New-ItemProperty -Path "HKCU:\Software\TestApplication" -Name "LastRun" -Value (Get-Date) -PropertyType String -Force
}

# Process creation detection
Add-MisleadingComments "Running system utility"
$processLaunch = {
    Start-Process -WindowStyle Hidden -FilePath "cmd.exe" -ArgumentList "/c echo Test > C:\Temp\test_output.txt"
}

# Defender manipulation
$defenderCheck = {
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
}

# Base64 encoded PowerShell script - actually just lists running services
$complexBase64 = "JHNlcnZpY2VzID0gR2V0LVNlcnZpY2UgfCBXaGVyZS1PYmplY3QgeyRfLlN0YXR1cyAtZXEgJ1J1bm5pbmcnfQpmb3JlYWNoICgkc2VydmljZSBpbiAkc2VydmljZXMpIHsKICAgIFdyaXRlLUhvc3QgIlNlcnZpY2U6ICIgKyAkc2VydmljZS5OYW1lICsgIiAtIERpc3BsYXlOYW1lOiAiICsgJHNlcnZpY2UuRGlzcGxheU5hbWUKfQ=="

# Uncomment to execute
# $decodedComplexScript = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($complexBase64))
# Invoke-Expression $decodedComplexScript

# Generate random large dataset to make the script longer and more complex
Add-MisleadingComments "Generating analysis data"
$randomData = @()
for ($i = 0; $i -lt 100; $i++) {
    $randomData += [PSCustomObject]@{
        ID = Get-Random -Minimum 1000 -Maximum 9999
        Name = "Process-$i"
        Priority = Get-Random -Minimum 1 -Maximum 5
        Status = (Get-Random -InputObject @("Running", "Stopped", "Suspended", "Unknown"))
    }
}

# More intentionally suspicious patterns
$chainedOperations = @'
Get-Service | 
    Where-Object {$_.Status -eq 'Running'} | 
    ForEach-Object {
        $_.DisplayName
        $path = Join-Path $env:TEMP "$($_.Name).log"
        $_.Name | Out-File -FilePath $path
    }
'@

# Multiple techniques combined
function Invoke-ObfuscatedOperation {
    param(
        [string]$Operation,
        [string]$Target
    )
    
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$Operation on $Target"))
    $command = "Write-Output `"Executing: $encoded`""
    
    return $command
}

$suspiciousCommand = Invoke-ObfuscatedOperation -Operation "Analyze" -Target "SystemProcesses"
# Invoke-Expression $suspiciousCommand

# Extremely long line with multiple concatenated strings to test parser
$extremelyLongCommand = "Get-" + "Process" + " | " + "Where-Object" + " {" + "$_" + "." + "WorkingSet" + " -gt" + " 50MB" + "}" + " | " + "Sort-Object" + " -Property" + " WorkingSet" + " -Descending" + " | " + "Select-Object" + " -First" + " 10" + " | " + "Format-Table" + " -Property" + " Name," + "ID," + "WorkingSet," + "Path" + " -AutoSize"

# Nested obfuscation with multiple techniques
$nestedObfuscation = @"
    `$var1 = [char]71 + [char]101 + [char]116 + [char]45 + [char]72 + [char]111 + [char]115 + [char]116;
    `$var2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("LUNvbXB1dGVyTmFtZSBsb2NhbGhvc3Q="));
    `$fullCmd = `$var1 + " " + `$var2;
    Invoke-Expression `$fullCmd
"@

# Extra long section with more obfuscation 
Add-MisleadingComments "Finalizing operations"
for ($j = 0; $j -lt 20; $j++) {
    $randomServiceName = "svc" + (Get-Random -Minimum 1000 -Maximum 9999)
    $randomCommand = "Get-Service -Name '*$randomServiceName*'" -replace "svc", "s" + "v" + "c"
    
    # This would normally execute the random commands but is commented out
    # Invoke-Expression $randomCommand
    
    # More obfuscated strings
    $obfuscatedChar = [char](71 + $j % 5)
    $moreChars = ""
    for ($k = 0; $k -lt 5; $k++) {
        $moreChars += [char](65 + ($j + $k) % 26)
    }
    
    # Add some fake paths with environment variables
    $fakePath = Join-Path $env:TEMP "$moreChars.log"
    $alternativePath = "$env:USERPROFILE\Downloads\$randomServiceName.txt"
    
    # Add some registry paths that look suspicious
    $fakeRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\$randomServiceName"
}

Write-Host "Test script completed execution"

# Final Base64 encoded message - contains "Script has completed all operations. No actual harm done. This is only a test."
$finalMessage = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("Script has completed all operations. No actual harm done. This is only a test."))
Write-Host "Completion code: $finalMessage"
