"""CI gate: every wiki technique/payload page must surface "by context" or be explicitly exempt.

Runs scripts/wiki-wiring-audit.py and fails if any audited page is orphaned (neither wired via a
playbook fingerprint ref, a hunt-skill link, one hop through an anchor/hub, nor listed in
scripts/wiring-exempt.txt). Prevents new orphans as pages are added.
See docs/superpowers/specs/2026-07-08-wiki-context-wiring-design.md
"""
import glob
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "scripts", "wiki-wiring-audit.py")

# wiki/ is gitignored (local Obsidian content, not in the repo). In CI / a fresh checkout it is
# absent, so the coverage gates below can only run where the wiki actually exists. A silent
# module-level skip was invisible in CI (a skip reads like a pass), so the per-test skip is paired
# with test_wiki_wiring_gate_visible(), which ALWAYS runs and xfails LOUDLY when wiki is absent -
# a CI run then shows an xfail with a reason, never a silent pass.
_WIKI_PRESENT = bool(glob.glob(os.path.join(ROOT, "wiki", "techniques", "**", "*.md"), recursive=True))
_needs_wiki = pytest.mark.skipif(
    not _WIKI_PRESENT,
    reason="wiki/ not present (gitignored local content); wiring coverage gate runs locally only",
)


def _audit():
    out = subprocess.check_output([sys.executable, AUDIT, "--json"], cwd=ROOT, text=True)
    return json.loads(out)


def test_wiki_wiring_gate_visible():
    """Always collected: makes the wiki-wiring gate's status visible in CI instead of a silent
    skip. wiki present -> assert the auditor actually ran (gate live). wiki absent -> xfail with a
    loud reason so a skipped coverage gate is never mistaken for a green pass."""
    if not _WIKI_PRESENT:
        pytest.xfail("wiki/ absent (gitignored); wiki-wiring coverage gate was NOT exercised this "
                     "run - this is not a pass. Run locally with wiki/ present, or ship a wiki fixture.")
    data = _audit()
    assert data["total"] > 100, "wiring auditor produced no page set; gate is inert"
    assert "orphans" in data and "coverage_pct" in data


@_needs_wiki
def test_no_orphaned_wiki_pages():
    data = _audit()
    orphans = data["orphans"]
    assert not orphans, (
        f"{len(orphans)} wiki page(s) do not surface by context and are not exempt "
        f"(coverage {data['coverage_pct']}%). Wire each into playbook.json refs / a hunt-skill link / "
        f"a hub page, or add to scripts/wiring-exempt.txt with a reason.\nFirst 20: "
        + ", ".join(o["slug"] for o in orphans[:20])
    )


@_needs_wiki
def test_no_unwired_tools():
    """Every wiki/tools/ page must be recommended by some context (fingerprint tools/refs or a skill)."""
    data = _audit()
    orphans = data.get("tool_orphans", [])
    assert not orphans, (
        f"{len(orphans)} tool page(s) are not recommended by any context; add them to a fingerprint "
        f"`tools`/`refs` or link from a hunt skill, or exempt them.\n" + ", ".join(orphans)
    )


@_needs_wiki
def test_no_unwired_cheatsheets():
    """Every wiki/cheatsheets/ page must surface by context or be exempt."""
    data = _audit()
    orphans = data.get("cheat_orphans", [])
    assert not orphans, (
        f"{len(orphans)} cheatsheet(s) do not surface by context; wire into a fingerprint ref / hunt "
        f"skill, or exempt.\n" + ", ".join(orphans)
    )


@_needs_wiki
def test_coverage_reported():
    """Sanity: the auditor computes a coverage number over a non-trivial page set."""
    data = _audit()
    assert data["total"] > 100
    assert 0 <= data["coverage_pct"] <= 100
