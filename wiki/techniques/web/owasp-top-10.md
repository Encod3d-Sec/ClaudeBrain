---
title: "OWASP Top 10 (2021) - Map to Pages, CVEs, Payloads"
type: technique
tags: [owasp, web, methodology, reference, exploitation]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

# OWASP Top 10 (2021)

Each category mapped to a real-world breach, notable CVEs, the payload arsenal, the deep wiki pages, and the hunt skill. Use as the framework-level index over the web content.

## A01 - Broken Access Control
IDOR/BOLA, privilege escalation, forced browsing, missing function-level auth.
- **Real-world:** Optus (2022) - unauthenticated API exposed 9.8M records via sequential IDs (BOLA).
- **CVEs:** CVE-2023-7028 (GitLab reset-to-arbitrary-email ATO), CVE-2023-22515 (Confluence broken access -> admin).
- **Payloads:** `wiki/payloads/api.md` (BOLA/BFLA/mass-assign), `wiki/payloads/auth-bypass.md` (403->200).
- **Pages:** [[access-control]], [[account-takeover]], [[csrf]], [[api-security]]. **Skills:** `hunt-idor`, `hunt-api`, `hunt-auth`.

## A02 - Cryptographic Failures
Cleartext transport/storage, weak hashing, hardcoded keys, bad randomness.
- **Real-world:** Heartbleed mass memory leak; countless plaintext-password DB dumps.
- **CVEs:** CVE-2014-0160 (Heartbleed), ROBOT/padding-oracle classes.
- **Payloads/test:** [[cryptography-attacks]] (RSA/padding-oracle/hash-ext), JWT weak HS256 -> `wiki/payloads/jwt`.
- **Pages:** [[cryptography-attacks]], [[jwt-attacks]], [[session-management-attacks]]. **Skill:** `hunt-auth`.

## A03 - Injection
SQLi, XSS, OS command, SSTI, XXE, LDAP, NoSQL, XPath, CRLF.
- **Real-world:** Log4Shell (2021) mass RCE; SQLi behind most legacy data breaches (TalkTalk, Heartland).
- **CVEs:** CVE-2021-44228 (Log4Shell), CVE-2022-22965 (Spring4Shell), CVE-2017-5638 (Struts), CVE-2024-4577 (PHP-CGI).
- **Payloads:** `wiki/payloads/` -> [[sqli]], [[xss]], [[command-injection]], [[ssti]], [[xxe]], [[nosql]], [[lfi-path-traversal]].
- **Pages:** [[sql-injection]], [[xss]], [[os-command-injection]], [[ssti]], [[xxe]], [[ldap-injection]], [[nosql-injection]], [[xpath-injection]], [[crlf-injection]]. **Skills:** `hunt-sqli`, `hunt-xss`, `hunt-rce`, `hunt-injection`.

## A04 - Insecure Design
Logic flaws, missing controls by design, abusable workflows.
- **Real-world:** coupon/price/quantity abuse and refund loops in e-commerce; OTP/reset workflow gaps (top H1 paying class).
- **Payloads/test:** `wiki/payloads/` logic via [[business-logic]]; concurrency for [[race-conditions]].
- **Pages:** [[business-logic]], [[race-conditions]]. **Skill:** `hunt-bizlogic`.

## A05 - Security Misconfiguration
Default creds, verbose errors, exposed admin/debug, missing headers, open cloud storage, XXE.
- **Real-world:** exposed `.env`/`.git`/Actuator/S3 buckets leaking creds; default admin panels.
- **CVEs:** exposure class (Spring actuator heapdump, exposed Jenkins/consoles).
- **Payloads/find:** [[recon-dorks]], [[default-credentials]], [[xxe]], `/actuator/*`.
- **Pages:** [[reverse-proxy-attacks]], [[cors-sop]], [[clickjacking]], [[http-host-header-attacks]]. **Skills:** `hunt-rce`, `hunt-cloud`.

## A06 - Vulnerable and Outdated Components
Known-CVE dependencies and unpatched products.
- **Real-world:** Equifax (2017) - unpatched Struts CVE-2017-5638, 147M records; Log4Shell across the internet.
- **CVEs:** the whole [[cve-arsenal]] (perimeter + app-server + collaboration).
- **Find/exploit:** [[trivy]]/grype (deps), [[nuclei]] (`-tags cve,kev`), [[cve-arsenal]], [[nday-patch-diffing]].
- **Pages:** [[supply-chain-attacks]], [[cms-exploitation]]. **Skills:** `hunt-rce`, `nday`.

## A07 - Identification and Authentication Failures
Weak auth, broken session, MFA bypass, credential stuffing, weak reset.
- **Real-world:** credential-stuffing ATO waves; reset-poisoning takeovers across bug-bounty programs.
- **CVEs:** CVE-2023-7028 (GitLab ATO).
- **Payloads:** `wiki/payloads/auth-bypass.md`, `wiki/payloads/oauth-saml.md`, `wiki/payloads/jwt`.
- **Pages:** [[authentication-attacks]], [[account-takeover]], [[mfa-bypass]], [[session-management-attacks]], [[jwt-attacks]], [[oauth-attacks]], [[saml-attacks]]. **Skills:** `hunt-auth`, `hunt-federation`.

## A08 - Software and Data Integrity Failures
Insecure deserialization, unsigned updates, CI/CD compromise, dependency confusion.
- **Real-world:** SolarWinds/SUNBURST (2020), 3CX, codecov - trojaned build pipelines; xz backdoor (2024).
- **CVEs:** CVE-2023-46604 (ActiveMQ deser), CVE-2021-44228 (Log4Shell), Java/.NET deser chains.
- **Payloads:** `wiki/payloads/deserialization.md`.
- **Pages:** [[insecure-deserialization]], [[supply-chain-attacks]], `cicd-attacks`. **Skill:** `hunt-deserialization`.

## A09 - Security Logging and Monitoring Failures
Insufficient detection/response (long dwell time). Attacker angle: log injection/poisoning + evasion.
- **Real-world:** breaches undetected for months (avg dwell time); attackers wipe/forge logs.
- **Test/abuse:** [[crlf-injection]] (log forging), LFI log poisoning ([[lfi-path-traversal]]).
- **Pages:** [[pentest-methodology]], [[vuln-assessment]] (reporting side).

## A10 - Server-Side Request Forgery (SSRF)
Server fetches an attacker-controlled URL.
- **Real-world:** Capital One (2019) - SSRF -> EC2 IMDS role creds -> S3 -> 100M records. The canonical SSRF breach.
- **CVEs:** CVE-2021-26855 (Exchange ProxyLogon SSRF chain), Confluence/Jira SSRF.
- **Payloads:** `wiki/payloads/ssrf.md`, [[imds-cloud-metadata]]; PDF/headless [[headless-browser-attacks]].
- **Pages:** [[ssrf]], [[headless-browser-attacks]]. **Skills:** `hunt-ssrf`, `hunt-cloud`. **Chain:** [[attack-chains]] #1.

## Use
Map a finding to its category for reporting; pivot from a category to the deep page + payload arsenal to exploit. Recon -> [[recon-dorks]]; perimeter/known-CVE -> [[cve-arsenal]]; end-to-end -> [[attack-chains]].
