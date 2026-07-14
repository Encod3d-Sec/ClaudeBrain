---
title: "Bug Bounty Reporting and Dedup"
type: cheatsheet
tags: [bugbounty, reporting, dedup, cvss, methodology, web]
date_created: 2026-06-18
date_updated: 2026-06-18
sources: [hackerone-disclosure-guidelines, bugcrowd-vrt, firstcvss]
---

## Goal

Maximize accepted, non-duplicate, well-paid reports. A real bug with a weak report gets downgraded, duped, or closed N/A. This is the gate between a finding and a bounty. Pairs with the `triage`, `evidence`, and `find-lint` framework steps.

## Before writing: dedup + scope (do this first)

- **Re-read scope + policy.** Confirm asset, vuln class, and severity are eligible. Out-of-scope or excluded class = instant close.
- **Dedup search** (the top reason for $0):
  - Program's public disclosures / Hacktivity (HackerOne), Bugcrowd Crowdstream.
  - Google `site:target.com` + the bug; the program changelog / release notes (may already be fixed).
  - Search the CVE/advisory DBs if it is a known product n-day.
  - If the program lists "known issues", check there.
- **Confirm real impact**, not theory. If you cannot show a concrete consequence, escalate the bug or do not file it.

## What gets closed (avoid)

Self-XSS, missing security headers alone, clickjacking on non-sensitive pages, rate-limiting-only, descriptive error messages, no-impact CSRF (logout/non-state-changing), best-practice/"informational", theoretical issues with no PoC, automated-scanner output pasted raw. If you only have one of these, **chain it** into real impact or skip.

## Report structure (impact-first)

1. **Title** - vuln + asset + impact in one line: "Stored XSS in /profile bio leads to account takeover".
2. **Summary** - 2-3 sentences: what, where, why it matters.
3. **Steps to reproduce** - numbered, copy-pasteable, exact URLs/params/payloads, starting from a clean session. A triager must reproduce in under 5 minutes.
4. **Proof of concept** - minimal request/response or short video; for blind bugs include the OOB callback evidence (see [[oob-callbacks]]).
5. **Impact** - business consequence: whose data, how many accounts, money/PII/admin. Tie to the program's assets.
6. **Severity / CVSS** - vector string + score; map to the program's reward table (or Bugcrowd VRT).
7. **Remediation** - concrete fix, shows good faith and speeds triage.
8. **Supporting material** - screenshots/HAR, **redacted** (no live tokens/PII - run the `evidence` step).

## Severity framing

- Use CVSS 3.1/4.0 vector; justify each metric briefly. Do not inflate (triagers re-score and trust drops).
- Bugcrowd programs: map to **VRT** category, not just CVSS.
- Raise severity legitimately by **chaining**: IDOR + PII = higher; reflected XSS + no HttpOnly + sensitive action = ATO. See [[attack-chains]].

## Maximize payout

- Demonstrate the **worst realistic impact** with a working PoC (ATO > info leak > self-only).
- One clear primary impact per report; note secondary impacts briefly. Do not bundle unrelated bugs in one report (and do not split one bug into many - both annoy triagers).
- Provide a fix and a clean repro: faster triage = faster, fuller bounty.
- For chains, show the full path end to end so it is scored as the chain, not the weakest link.

## If marked duplicate / N/A

- Duplicate: accept gracefully; ask (politely) for disclosure once the original is resolved (builds reputation).
- N/A / Informational: provide a clearer impact PoC or a chain; if scope/impact was misread, give a concise, evidence-backed clarification once - do not argue.

## Quick reference

- HackerOne uses Markdown; keep code in fenced blocks, redact secrets.
- Lead with impact, not methodology. Triagers skim.
- Evidence redaction is mandatory before submit - cookies, tokens, PII, internal IPs.

## Sources

- HackerOne disclosure guidelines (slug: hackerone-disclosure-guidelines) (`https://docs.hackerone.com`).
- Bugcrowd Vulnerability Rating Taxonomy (slug: bugcrowd-vrt) (`https://bugcrowd.com/vulnerability-rating-taxonomy`).
- FIRST CVSS calculator (slug: firstcvss) (`https://www.first.org/cvss/calculator/3.1`).
