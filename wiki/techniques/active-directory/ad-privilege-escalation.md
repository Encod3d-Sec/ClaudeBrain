---
title: Active Directory – Privilege Escalation
type: technique
tags: [active-directory, genericall, kerberoasting, pass-the-hash, privilege-escalation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory – Privilege Escalation

## What it is

Privilege escalation in Active Directory (AD) leverages mis‑configurations, overly permissive ACLs, and credential‑related weaknesses to gain higher privileges such as Domain Admin, Enterprise Admin, or replication rights.

## How it works

AD privilege escalation chains ACL misconfigurations, credential weaknesses, delegation abuses, and trust relationships to elevate from a low-privileged domain user to Domain Admin or Enterprise Admin. Attackers enumerate the environment with tools like BloodHound to map the shortest privilege escalation path, then exploit weak ACEs, misconfigured delegation settings, or certificate templates along that path. Because AD is a flat trust model within a domain, any path to a DCSync-capable account or Domain Admins membership results in full domain compromise.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Overview
Privilege escalation in Active Directory (AD) leverages mis‑configurations, overly permissive ACLs, and credential‑related weaknesses to gain higher privileges such as Domain Admin, Enterprise Admin, or replication rights.

## Core Techniques

- **Kerberoasting** – Request service tickets for accounts with SPNs and crack the `krbtgt` hashes.
- **AS‑REP Roasting** – Target accounts with `DONT_REQ_PREAUTH` to obtain AS‑REP hashes without needing a pre‑auth ticket.
- **Pass‑the‑Hash / Pass‑the‑Ticket** – Reuse NTLM hashes or Kerberos tickets to authenticate as other users.
- **DCSync** – Abuse the `Replicating Directory Changes`/`All` rights to pull password hashes directly from the Domain Controller.
- **GenericAll / GenericWrite** – Manipulate ACLs to grant full control over objects (users, groups, computers).
- **RID Brute‑Force** – Enumerate low‑RID accounts by cycling the domain SID.

## Example Commands
```ps1
# Kerberoasting (PowerView)
Get-NetComputer -Unconstrained | % { Get-NetUser -SPN $_.distinguishedName }

# AS‑REP Roasting (Impacket)
GetNPUsers.py -no-preauth -usersfile users.txt -dc-ip 10.0.0.5

# DCSync (Impacket)
secretsdump.py -just-dc USER:PASS@DC

# GenericAll via Invoke-ACLPwn (PowerShell)
Invoke-ACLPwn -Target "DOMAIN\\TargetUser" -Permission GenericAll

# RID Brute‑Force (NetExec)
netexec smb 10.0.0.5 -u guest -p '' --rid-brute 2000 --log rid.txt
```

## Tools
- **PowerView / PowerSploit** – AD enumeration and ACL manipulation.
- **Impacket (GetNPUsers.py, secretsdump.py)** – AS‑REP and DCSync attacks.
- **bloodyAD** – Multi‑platform AD exploitation (hash extraction, ACL abuse).
- **Invoke‑ACLPwn** – Automates GenericAll/WriteDacl abuses.
- **NetExec** – RID brute‑force.

## References
- *InternalAllTheThings – Active Directory – Privilege Escalation* (various markdown files).
- *Kerberoasting – FireEye*.
- *DCSync – Matt Graeber*.
- *Pass‑the‑Hash – Mudge*.

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[bloodhound]]
- [[impacket]]
- [[netexec]]
- Also uses (no dedicated page yet): PowerView, PowerSploit

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[active-directory-access-controls-aclace]]
- [[active-directory-gpo]]
- [[active-directory-group-policy-objects]]
- [[active-directory-machine-account-quota]]
- [[active-directory-read-only-domain-controller]]
- [[child-domain-to-forest-compromise-sid-hijacking]]
- [[password-dmsa]]
- [[privexchange]]
- [[trust-privileged-access-management]]
- [[wfp-privilege-escalation]]
