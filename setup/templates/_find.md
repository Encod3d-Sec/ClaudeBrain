---
title: "<short title>"
type: finding
severity: MEDIUM
class: ""            # optional: canonical vuln class (ssrf/idor/rce/...) for chain triggers + coverage; fuzzy-inferred from title if blank
status: RESEARCH
cvss: ""
affected: ""
date_created: "{{DATE}}"
sources: []
---

# <short title>

## Description

What the vulnerability is, where it lives, and the root cause. One tight paragraph.

## Proof of Concept

Numbered, reproducible steps. Exact requests/commands in fenced code blocks. A reviewer must be able to replay this verbatim.

```
# step 1 ...
```

## Impact

Concrete technical and business impact. What an attacker gains. Tie to data/access, not theory.

## Remediation

How to fix it. Specific, actionable.

## References

CVE / advisory / docs links.

<!-- canonical-vocab (single source of truth; read by tests/test_skill_contract.py, do not drift)
find_filename_placeholder: FIND-XXX-SEVERITY-short-slug.md
vuln_index_status: CONFIRMED | PARTIAL
-->

