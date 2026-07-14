---
title: Trust - Relationship
type: technique
tags: [active-directory, enumeration, forest, reference-import, windows]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Trust - Relationship

## What it is

Technical reference for **Trust - Relationship** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Active Directory domain trusts define which domains accept authentication from users in other domains; one-way trusts allow users in the trusted domain to access resources in the trusting domain, while two-way trusts allow bidirectional access. Attackers enumerate trust relationships using `nltest`, `Get-ADTrust`, or BloodHound to identify paths from compromised domains to higher-privileged domains or forests. Cross-domain attacks exploit the trust key shared between domains to forge tickets that carry SID history, escalating from child domain compromise to parent domain or cross-forest access.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

- One-way
    - Domain B trusts A
    - Users in Domain A can access resources in Domain B
    - Users in Domain B cannot access resources in Domain A
- Two-way
    - Domain A trusts Domain B
    - Domain B trusts Domain A
    - Authentication requests can be passed between the two domains in both directions

## Enumerate trusts between domains

- Native `nltest`

```powershell
nltest /trusted_domains
```

- PowerShell `GetAllTrustRelationships`

```powershell
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

SourceName          TargetName                    TrustType      TrustDirection
----------          ----------                    ---------      --------------
domainA.local      domainB.local                  TreeRoot       Bidirectional
```

- netexec module `enum_trusts`

```powershell
nxc ldap <ip> -u <user> -p <pass> -M enum_trusts 
```

## Exploit trusts between domains

:warning: Require a Domain-Admin level access to the current domain.

| Source     | Target  | Technique to use  | Trust relationship  |
|---|---|---|---|
| Root      | Child  | Golden Ticket + Enterprise Admin group (Mimikatz /groups) | Inter Realm (2-way)  |
| Child     | Child  | SID History exploitation (Mimikatz /sids)                 | Inter Realm Parent-Child (2-way)  |
| Child     | Root   | SID History exploitation (Mimikatz /sids)                 | Inter Realm Tree-Root (2-way)  |
| Forest A  | Forest B  | PrinterBug + Unconstrained delegation ?  | Inter Realm Forest or External (2-way)  |

## References

- [External Trusts Are Evil - 14 March 2023 - Charlie Clark (@exploitph)](https://exploit.ph/external-trusts-are-evil.html)
- [Carlos Garcia - Rooted2019 - Pentesting Active Directory Forests public.pdf](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
- [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[bloodhound]]
- [[mimikatz]]
- [[netexec]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
