---
name: triage
description: Finding validation gate - 7-Question triage adapted for FIND schema. Run before moving any FIND from Research to Completed. One NO = keep in Research. All YES = move to Completed, then run /evidence.
---

# Triage: Finding Validation Gate

Use BEFORE moving any FIND from `Vulns/Research/` to `Vulns/Completed/`.

One wrong answer = keep the finding in Research. Move on to next test class.

---

## THE 7-QUESTION GATE

Ask in order. One NO = STOP for this finding.

### Q1: Can an attacker use this RIGHT NOW, step by step?
Complete this template:
```
Setup:   I need [own account / another user's ID / no account / internal access]
Request: [exact HTTP method, URL, headers, body -- copy-paste ready]
Result:  I can [read / modify / delete / execute] [exact data or action]
Impact:  The real-world consequence is [specific impact]
```
If you CANNOT write the Request line as a real reproducing command -> keep in Research.

### Q2: Is the impact within engagement scope?
- Does it affect an in-scope asset?
- Does the impact match the severity level being claimed?
- Not a third-party service the target merely uses?

### Q3: Is the root cause in an in-scope asset?
- Production asset (not staging/dev unless in scope)
- Not out-of-scope subsidiary or third-party

### Q4: Does it require privileged access that an attacker cannot realistically obtain?
- "Admin can do X" = not a finding
- "Non-admin can do X that only admin should do" = valid
- Pre-auth or low-auth is highest value

### Q5: Is this already known or documented?
- Check Vuln-index.md - not already listed?
- Check Deadends.md - not already investigated and closed?
- Not design-documented behaviour?

### Q6: Can you prove impact beyond "technically possible"?
- XSS -> show actual session theft or action execution, not just alert(1)
- SSRF -> confirm OOB callback (DNS/HTTP), not just URL echo in error message
- SQLi -> show actual data extracted from a real table
- IDOR -> show actual other-user data in response body, not just 200 status

### Q7: Not on the Never-Promote list?
Never promote to Completed without a chain:
```
Self-XSS only (no CSRF trigger)
Open redirect alone (no OAuth/ATO chain)
CORS wildcard without credentialed exfil PoC
SSRF DNS-only (no internal service access)
Rate limit without demonstrated impact
Version banner alone
Missing headers alone (no impact PoC)
```

---

## Pre-Severity Gate (run before labelling CRITICAL or HIGH)

1. Have you validated the FULL chain to attacker-attainable impact, or only one primitive?
2. What does the attacker walk away with in one concrete sentence?
3. Have you reproduced the full chain end-to-end at least twice?
4. Is there a validation step (signature check, audience check, MFA) still gating the chain?

A "primitive confirmed" != exploitable. Downgrade until the gate is bypassed.

---

## Decision

| Result | Action |
|--------|--------|
| All 7 YES + Pre-Severity Gate clean | Move FIND to Vulns/Completed/. Update status in Vuln-index.md. Run `python3 scripts/find-lint.py` and fix any gaps (Description/PoC/Impact/Remediation + CVSS for HIGH/CRITICAL) so it is report-ready. Then run /evidence. |
| Any NO | Keep in Vulns/Research/. Update status to PARTIAL (reason) in Vuln-index.md. Document what is missing. |
| Q7 chain required | Move to Vulns/Research/ with note "chain required: [what is needed]". |
