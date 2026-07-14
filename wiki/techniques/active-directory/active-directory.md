---
title: "Active Directory Hub"
type: technique
tags: [active-directory, enumeration, kerberos, lateral-movement, persistence, windows]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [cpts-common-services, InternalAllTheThings]
---

## What it is

**Active Directory (AD)** is Microsoft’s LDAP and Kerberos-backed identity platform for enterprises. Attackers abuse misconfigurations across enumeration, credential access, lateral movement, persistence, federation, PKI/ADCS, and trusts.

## How it works

AD ties users, groups, computers, GPOs, certificates, and domain trusts into a single graph. Most paths start with read access (LDAP, SMB, BloodHound) and chain object-level permissions (ACL/ACE), Kerberos tickets, delegated auth, certificate templates, or trust relationships into domain-wide impact.

## Attack phases

- **Recon and enumeration**: [[ad-enumeration]], [[kerberos-attacks]], cheatsheet commands in [[ad-cheatsheet|Active Directory cheatsheet]]
- **Credential access**: [[pass-the-hash]], [[password-cracking]], roasting and ticket abuse documented under [[kerberos-attacks]]
- **Lateral movement**: [[ad-lateral-movement]]
- **Persistence**: [[ad-persistence]]
- **PKI**: [[adcs]], fine-grained reference pages such as [[active-directory-certificate-esc-attacks]]
- **ACL/ACE escalation**: [[active-directory-access-controls-aclace]]

## Reference import corpus

Roughly **170** sister pages sourced from Swisskyrepo *InternalAllTheThings* share `sources: [InternalAllTheThings]`. Entry point: [[internal-all-the-things]]. Typical filenames group by prefix (for example `azure-ad---`, `aws---`, `kerberos-delegation---`, `password---`). Each page wraps the upstream payload material inside the standard methodology sections from `docs/page-types.md`, then keeps the original imported body under **Methodology**.

## Tools

Cross-check [[netexec]], [[certipy]], [[evil-winrm]], and tool notes inside [[ad-cheatsheet|Active Directory cheatsheet]] during engagements.
