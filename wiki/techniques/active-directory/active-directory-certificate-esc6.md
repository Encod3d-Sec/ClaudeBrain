---
title: Active Directory - Certificate ESC6
type: technique
tags: [active-directory, adcs, certificates, esc6, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC6

## What it is

> If this flag is set on the CA, any request (including when the subject is built from Active Directory) can have user defined values in the subject alternative name.

## How it works

ESC6 abuses the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set at the CA level, which instructs the CA to accept attacker-supplied SANs in any certificate request regardless of the template's individual settings. Even templates that do not normally permit arbitrary SANs become exploitable because the CA overrides those restrictions globally. An attacker requests a certificate for any enrolled template while specifying a privileged user's UPN as the SAN, obtaining a credential that authenticates as that user.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

> If this flag is set on the CA, any request (including when the subject is built from Active Directory) can have user defined values in the subject alternative name.

**Exploitation**

* Use [Certify.exe](https://github.com/GhostPack/Certify) to check for **UserSpecifiedSAN** flag state which refers to the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

```ps1
Certify.exe cas
```

* Request a certificate for a template and add an altname, even though the default `User` template doesn't normally allow to specify alternative names

```ps1
.\Certify.exe request /ca:dc.domain.local\domain-DC-CA /template:User /altname:DomAdmin
```

**Mitigation**

* Remove the flag: `certutil.exe -config "CA01.domain.local\CA01" -setreg "policy\EditFlags" -EDITF_ATTRIBUTESUBJECTALTNAME2`

## References

* [AD CS: from ManageCA to RCE - February 11, 2022 - Pablo Martínez, Kurosh Dabbagh](https://web.archive.org/web/20220212053945/http://www.blackarrow.net/ad-cs-from-manageca-to-rce//)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- Also uses (no dedicated page yet): Certify

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
