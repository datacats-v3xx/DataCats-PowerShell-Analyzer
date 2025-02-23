# -------------------------------------------------------
# Sysmon + SwiftOnSecurity Deployment Script For That Azz
# -------------------------------------------------------

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$sysmonZipPath = "$env:TEMP\Sysmon.zip"
$sysmonExtractPath = "$env:TEMP\Sysmon"
$configPath = "$env:TEMP\sysmonconfig-export.xml"
$sysmonExePath = "$sysmonExtractPath\Sysmon64.exe"
$logFile = "$env:TEMP\Sysmon_Install_Log.txt"

Function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp - $message"
    Write-Output $entry
    $entry | Out-File -FilePath $logFile -Append
}

Function Download-File {
    param ([string]$url, [string]$destPath)
    try {
        Write-Log "Downloading $url..."
        Invoke-WebRequest -Uri $url -OutFile $destPath -ErrorAction Stop
        Write-Log "Downloaded $url to $destPath"
    } catch {
        Write-Log "Failed to download $url. Error: $_"
        throw $_
    }
}

Function Unblock-Script {
    param ([string]$filePath)
    try {
        if (Test-Path $filePath) {
            Write-Log "Unblocking $filePath..."
            Unblock-File -Path $filePath
            Write-Log "$filePath successfully unblocked."
        } else {
            Write-Log "File $filePath not found, skipping unblocking."
        }
    } catch {
        Write-Log "Failed to unblock $filePath. Error: $_"
    }
}

Function Install-Sysmon {
    param ([string]$exePath, [string]$configFile)
    try {
        Write-Log "Installing Sysmon with configuration..."
        & $exePath -accepteula -i $configFile
        Write-Log "Sysmon installation complete."
    } catch {
        Write-Log "Sysmon installation failed. Error: $_"
        throw $_
    }
}

Function Update-SysmonConfig {
    param ([string]$exePath, [string]$configFile)
    try {
        Write-Log "Updating Sysmon configuration..."
        & $exePath -c $configFile
        Write-Log "Sysmon configuration updated successfully."
    } catch {
        Write-Log "Sysmon configuration update failed. Error: $_"
        throw $_
    }
}

Function Verify-Sysmon {
    Write-Log "Verifying Sysmon installation..."
    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-Log "Sysmon service not found. Installation may have failed."
        return $false
    } else {
        Write-Log "Sysmon service status: $($service.Status)"
        return $true
    }
}

Function Clean-Old-Install {
    Write-Log "Checking for existing Sysmon installation..."
    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Existing Sysmon installation found. Uninstalling..."
        & $sysmonExePath -u force
        Start-Sleep -Seconds 5
        Write-Log "Old Sysmon installation removed."
    } else {
        Write-Log "No existing Sysmon installation found."
    }
}

try {
    Write-Log "=== Sysmon Deployment Script Started ==="

    # 1. Download Sysmon
    if (-Not (Test-Path $sysmonZipPath)) {
        Download-File -url $sysmonUrl -destPath $sysmonZipPath
    } else {
        Write-Log "Sysmon.zip already exists at $sysmonZipPath"
    }

    # 2. Extract Sysmon
    if (-Not (Test-Path $sysmonExtractPath)) {
        Write-Log "Extracting Sysmon..."
        Expand-Archive -Path $sysmonZipPath -DestinationPath $sysmonExtractPath -Force
        Write-Log "Sysmon extracted to $sysmonExtractPath"
    } else {
        Write-Log "Sysmon already extracted at $sysmonExtractPath"
    }

    # 3. Unblock Sysmon Executable To Prevent Fuck Ups
    Unblock-Script -filePath $sysmonExePath

    # 4. Download SwiftOnSecurity configuratorini
    Download-File -url $configUrl -destPath $configPath

    # 5. Unblock the Sysmon Config File To Prevent Fuck Ups
    Unblock-Script -filePath $configPath

    # 6. Run the Train On Old Install
    Clean-Old-Install

    # 7. Install Sysmon with configuratorini
    Install-Sysmon -exePath $sysmonExePath -configFile $configPath

    # 8. Verify That Bish
    if (Verify-Sysmon) {
        Write-Log "Sysmon installed and running successfully."
    } else {
        Write-Log "Sysmon installation failed. Check the logs."
    }

    Write-Log "=== Sysmon Deployment Script Completed Successfully ==="
} catch {
    Write-Log "Script execution failed with error: $_"
}

# Log It In Case of Fuck Up
Get-Content $logFile
