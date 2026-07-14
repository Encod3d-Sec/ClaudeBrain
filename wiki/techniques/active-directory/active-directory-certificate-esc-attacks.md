---
title: Active Directory - Certificate ESC Attacks
type: technique
tags: [active-directory, adcs, certificates, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC Attacks

## What it is

Technical reference for **Active Directory - Certificate ESC Attacks** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

AD CS ESC attacks exploit misconfigurations in Active Directory Certificate Services, such as overly permissive certificate templates, weak CA settings, and inadequate object-level ACEs. Each ESC variant (ESC1 through ESC15) targets a distinct misconfiguration class, ranging from template enrollment settings that allow SAN spoofing, to CA-level flags and object permissions that allow privilege escalation or credential forgery. The common outcome is the ability to issue or manipulate certificates that authenticate as privileged domain users without knowing their passwords.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

* [ESC1 - Misconfigured Certificate Templates](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc01/)
* [ESC2 - Misconfigured Certificate Templates](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc02/)
* [ESC3 - Misconfigured Enrollment Agent Templates](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc03/)
* [ESC4 - Access Control Vulnerabilities](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc04/)
* [ESC5 - Vulnerable PKI Object Access Control](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc05/)
* [ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc06/)
* [ESC7 - Vulnerable Certificate Authority Access Control](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc07/)
* [ESC8 - Web Enrollment Relay](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc08/)
* [ESC9 - No Security Extension](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc09/)
* [ESC10 - Weak Certificate Mapping](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc10/)
* [ESC11 - Relaying NTLM to ICPR](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc11/)
* [ESC12 - ADCS CA on YubiHSM](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc12/)
* [ESC13 - Issuance Policy](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc13/)
* [ESC14 - altSecurityIdentities](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc14/)
* [ESC15 - EKUwu Application Policies - CVE-2024-49019](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc15/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
