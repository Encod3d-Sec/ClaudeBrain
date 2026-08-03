---
name: disclosure
description: Drive responsible disclosure of a proven finding to a CVE. Package the report, find the vendor contact, report privately, coordinate a timeline, request the CVE (vendor CNA / GitHub / MITRE), and publish an advisory. Closes the research loop. Triggers - "disclose", "request a cve", "report this to the vendor".
---

# Disclosure: Finding -> CVE

Turn a proven, novel vulnerability into a coordinated disclosure and a published CVE. Pairs with the `research` skill (a finding in `findings.md`) or an engagement FIND. Read [[responsible-disclosure]] first.

## Gate (READ FIRST)
- The finding must be **proven + reproducible** (minimal PoC, affected versions, impact) and **novelty-checked** (not an existing CVE). If not, go back to the `research` skill.
- Confirm you are **authorised / in safe-harbor** for the target. No authorization -> do not proceed (CFAA / Computer Misuse Act). Research on public software you can lawfully analyze is fine; testing live third-party systems needs permission.

## Procedure
1. **Package the report** from the finding: title, affected + fixed/tested versions, CWE class, CVSS vector + score, clear repro steps, minimal PoC, impact, suggested remediation, your contact. Redact any real data.
2. **Find the contact** (in order): `/.well-known/security.txt`, `SECURITY.md`, `security@<vendor>`, vendor PSIRT, a bug-bounty platform if they run one, GitHub private vulnerability reporting for OSS, else CERT/CC.
3. **Report privately** over that channel; PGP-encrypt if a key is published. Professional, specific, non-extortive. Offer to validate the fix.
4. **Coordinate a timeline** - propose ~90 days; track it; escalate to CERT/CC if the vendor goes dark past the deadline.
5. **Request the CVE:** vendor CNA assigns it; for OSS open a GitHub Security Advisory (GitHub issues the CVE); otherwise MITRE CVE request form (CNA of last resort). Supply product, versions, CWE, impact, reference.
6. **Publish the advisory** after fix/deadline: CVE ID, affected/fixed versions, CWE, CVSS, description, PoC, impact, remediation, timeline, credit. Mirror to the researcher's blog/GitHub for the portfolio.

## Output
- A ready-to-send **disclosure report** (draft) and a **public advisory** (draft) saved under the project: `raw/research/<project>/advisory.md` (and the contact + timeline tracked in `findings.md`).
- Update the finding status: candidate -> reported -> `CVE-<id>` -> published.

## Wiki feedback
Reusable disclosure lesson (vendor process quirk, CNA tip) -> update [[responsible-disclosure]]. The vuln technique itself -> the matching `wiki/techniques/` page via `research-ingest`.

Report: report + advisory drafts, contact channel, and the disclosure timeline.
