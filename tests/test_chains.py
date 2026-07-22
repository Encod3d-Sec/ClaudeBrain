"""Tests for chains.json + its _engagement readers + phase_explicit."""
import os

import _engagement


def _mkfind(eng, name, fm, body="x"):
    d = eng / "Vulns"
    d.mkdir(parents=True, exist_ok=True)
    fmtxt = "\n".join(f"{k}: {v}" for k, v in fm.items())
    (d / name).write_text(f"---\n{fmtxt}\n---\n\n# {fm.get('title', name)}\n\n{body}\n",
                          encoding="utf-8")


VULN_INDEX = """---
type: engagement-vuln-index
---

# Vuln Index

## CRITICAL

| ID | Title | Host | Status |
|----|-------|------|--------|
| FIND-001 | SSRF in fetch | web01 | CONFIRMED |

## HIGH

| ID | Title | Host | Status |
|----|-------|------|--------|
| FIND-002 | IDOR on profile | web02 | PARTIAL (needs victim id) |
| FIND-003 | XSS reflected | web03 | VERSION CONFIRMED / PoC pending |
| FIND-004 | Old bug | web04 | CLOSED |

## Severity Count

| Severity | Count | Confirmed | Notes |
|----------|-------|-----------|-------|
| Critical | 1 | 1 | CONFIRMED |
"""


def test_vuln_index_confirmed_ids(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Vuln-index.md").write_text(VULN_INDEX, encoding="utf-8")
    ids = _engagement._vuln_index_confirmed_ids(str(eng))
    # CONFIRMED + PARTIAL kept; VERSION CONFIRMED / CLOSED / Severity-Count excluded
    assert ids == {"FIND-001": "web01", "FIND-002": "web02"}


def test_confirmed_findings_gated_and_classed(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "Vuln-index.md").write_text(VULN_INDEX, encoding="utf-8")
    # FIND-001 has explicit class; FIND-002 relies on fuzzy title; FIND-003 is not confirmed
    _mkfind(eng, "FIND-001-CRITICAL-ssrf-fetch.md",
            {"title": "SSRF in fetch", "class": "ssrf", "affected": "web01", "status": "Research"})
    _mkfind(eng, "FIND-002-HIGH-idor-profile.md",
            {"title": "IDOR on profile", "affected": "web02", "status": "Research"})
    _mkfind(eng, "FIND-003-MEDIUM-xss.md",
            {"title": "XSS reflected", "affected": "web03", "status": "Research"})
    got = {(f["class"], f["asset"], f["severity"]) for f in _engagement.confirmed_findings(str(eng))}
    assert ("ssrf", "web01", "CRITICAL") in got     # explicit class + severity from filename
    assert ("idor", "web02", "HIGH") in got         # fuzzy class from title
    assert not any(a == "web03" for _, a, _ in got)  # not confirmed -> excluded


def test_confirmed_findings_missing_files(tmp_path):
    assert _engagement.confirmed_findings(str(tmp_path / "nope")) == []
