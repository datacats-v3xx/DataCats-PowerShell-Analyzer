Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig-export.xml"
& "$env:TEMP\Sysmon\Sysmon64.exe" -c "$env:TEMP\sysmonconfig-export.xml"
