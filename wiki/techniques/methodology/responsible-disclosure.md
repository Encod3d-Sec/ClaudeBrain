---
title: "Responsible Disclosure and CVE Assignment"
type: technique
tags: [methodology, disclosure, cve, reporting, research, ethics]
phase: reporting
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## What it is

The process of reporting a discovered vulnerability to the vendor, coordinating a fix, and getting a **CVE** assigned and an advisory published, ethically and legally. This is what turns a finding from the `research` skill into a credential: published CVEs are the currency of a security-research reputation.

## How it works

Coordinated disclosure keeps the bug private while the vendor builds a fix, then publishes once users can patch. A **CVE ID** (Common Vulnerabilities and Exposures) is issued by a **CNA** (CVE Numbering Authority) - the vendor if they are one, otherwise a third-party CNA or MITRE as the CNA of last resort.

## Attack phases
Reporting / post-research (after a finding is proven and novel - see the `research` skill, step 7-8).

## Prerequisites
- A **proven, reproducible** finding with affected versions, impact, and a minimal PoC (research `findings.md`).
- Confirmed **novelty** (not already a known/fixed CVE).

## Methodology

### 1. Package the report
Title, affected + tested versions, vuln class (CWE), CVSS vector + score, clear reproduction steps, minimal PoC, impact, suggested remediation, and your contact. No real victim data; redact anything sensitive.

### 2. Find the contact (in order)
```
/.well-known/security.txt   (RFC 9116: contact, encryption, policy)
SECURITY.md in the repo;  security@<vendor>;  vendor PSIRT page
Bug bounty platform (HackerOne/Bugcrowd) if the vendor runs one
GitHub: private vulnerability reporting / Security Advisory (for OSS repos)
No response -> CERT/CC (kb.cert.org) coordinates on your behalf
```

### 3. Report privately
Send the package over the stated channel; encrypt with the vendor PGP key if published. Be specific, professional, non-extortive. Offer to clarify and to validate the fix.

### 4. Coordinate a timeline
Agree a disclosure date - **90 days** is the common industry default (Project Zero). Stay responsive; re-confirm the fix when shipped. Escalate to CERT/CC if the vendor goes silent past the deadline.

### 5. Request the CVE
```
Vendor is a CNA            -> they assign the CVE in their advisory.
OSS on GitHub              -> open a GitHub Security Advisory; GitHub (a CNA) issues the CVE (GHSA + CVE).
Third-party CNA covers it  -> request via that CNA (e.g. a program's platform).
None of the above          -> MITRE CVE Request form (cveform.mitre.org), CNA of last resort.
```
Provide: product, affected versions, vuln type (CWE), impact, and a reference. The ID is **RESERVED**, then **PUBLISHED** with details after disclosure.

### 6. Publish the advisory
After the fix (or the agreed deadline), publish: title, CVE ID, affected/fixed versions, CWE, CVSS vector, description, PoC, impact, remediation, timeline, and credit. Mirror to your blog / GitHub for the portfolio.

## Bypasses and variants
- **Disclosure models:** coordinated/responsible (private -> fix -> public, default); full disclosure (public immediately - last resort against an unresponsive/hostile vendor); non-disclosure (private only).
- **Bounty vs CVE:** a bug bounty pays but may forbid public disclosure; a CVE builds public reputation. Some programs allow both - check the policy.

## Detection and defence
Vendor side: publish a `security.txt` + `SECURITY.md`, run a PSIRT/VDP, become a CNA, and patch within the agreed window.

## Legal and ethics (read first)
Stay within scope and the program's **safe-harbor** terms. Do not access/exfiltrate real user data, pivot, or persist beyond proving impact. Unauthorized testing can violate the CFAA (US) / Computer Misuse Act (UK) / equivalent - no authorization, no testing. Never extort ("pay or I publish").

## Tools
`security.txt`, FIRST CVSS calculator, CWE list, PGP/age (encrypted reports), CVE/NVD + GHSA search (novelty + references). Driven by the `disclosure` skill; findings come from the `research` skill. Report quality: [[vulnerability-reports]], [[vuln-assessment]].

## Sources
