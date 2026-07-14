---
name: coverage
description: Show per-asset vuln-class coverage gaps for the active engagement so nothing in scope is skipped. Use when asked "coverage", "what haven't we tested", "test gaps", "are we thorough", or before calling an engagement done.
---

# Coverage

Systematic thoroughness: which applicable vuln classes have NOT been tested per asset.

## Run
```
python3 scripts/coverage.py        # gaps per asset
python3 scripts/coverage.py -v     # + tested/applicable detail
```
`applicable = base classes for the engagement type (scripts/coverage-classes.json) + classes implied by the asset's tech (playbook fingerprints)`. `gaps = applicable - tested`.

## Then (model)
1. For each asset with gaps, the gap list IS the to-do. Prioritise by impact + the `[test]` moves from `next_move.py` (fingerprint-targeted).
2. Pull payloads from `wiki/payloads/<class>` for each untested class.
3. After testing a class on an asset, **update `targets/<eng>/coverage.md`**: add the class to that asset's `tested` column (and any finding to `findings`). Otherwise the gap recurs.
4. An asset shows `complete` only when every applicable class is in `tested`.

## Discipline
- Respect scope: out-of-scope assets are already excluded by coverage.py.
- "Complete" means tested, not necessarily clean - record findings separately as FINDs.
- Don't pad `tested` without actually testing; this checklist only helps if honest.
