#!/usr/bin/env python3
"""find-lint.py - quality gate for finding files before they reach a report.

Scans targets/<active>/Vulns/**/FIND-*.md and checks each finding is complete +
reproducible: required sections present and non-empty, valid severity in the
filename, and (for HIGH/CRITICAL) a CVSS vector + affected target. Reports gaps.

  python3 scripts/find-lint.py        # lint active engagement's findings
  python3 scripts/find-lint.py -v     # show passing files too

Exit 1 if any finding is incomplete (usable as a pre-report gate).
"""
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement  # noqa: E402

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def cvss_band(score):
    """CVSS v3.1 severity band for a base score, or None if out of range."""
    if score is None:
        return None
    if score == 0:            return "INFO"      # 0.0 = None; findings use INFO
    if score < 4.0:           return "LOW"
    if score < 7.0:           return "MEDIUM"
    if score < 9.0:           return "HIGH"
    if score <= 10.0:         return "CRITICAL"
    return None


# A score after a dash separator ("<vector> - 9.8"). The leading dash is what keeps
# the search from grabbing the "3.1" out of a bare vector like "CVSS:3.1/AV:N/...".
_SCORE_RE = re.compile(r"[—\-]\s*(10(?:\.0)?|\d(?:\.\d)?)\b")
# A value that is ONLY a number ("cvss: 9.8"), with no vector present.
_BARE_SCORE_RE = re.compile(r"^(10(?:\.0)?|\d(?:\.\d)?)$")


def cvss_score(fmt):
    """Extract the numeric CVSS base score from the frontmatter `cvss:` value, or None."""
    m = re.search(r"^cvss:\s*(.+)$", fmt, re.M | re.I)
    if not m:
        return None
    val = m.group(1).strip()
    sm = _SCORE_RE.search(val)
    if not sm and "/" not in val:   # no dash-score form and not a vector -> accept a bare number
        sm = _BARE_SCORE_RE.match(val)
    if not sm:
        return None
    try:
        v = float(sm.group(1))
    except ValueError:
        return None
    return v if 0.0 <= v <= 10.0 else None


# required section -> accepted heading regex (case-insensitive). The canonical
# wording is setup/templates/_find.md (the single source of truth): Description /
# Proof of Concept / Impact / Remediation, with References optional. The extra
# alternations are back-compat aliases for findings written before the templates
# were reconciled, so pre-existing pentest/bugbounty findings still pass. Keep the
# _find.md wording first in each alternation; test_find_md_headings_lock_to_find_lint
# fails if _find.md and this table drift.
REQUIRED = {
    "Description": r"^#+\s*(description|summary)",
    "Proof of Concept": r"^#+\s*(proof of concept|poc|reproduction|repro|steps)",
    "Impact": r"^#+\s*impact",
    "Remediation": r"^#+\s*(remediation|fix|mitigation)",
}
FNAME_RE = re.compile(r"FIND-\d+-([A-Z]+)-", re.I)


def find_files(d):
    """Report-bound findings only: skip Skipped*/False* dirs (not deliverables)."""
    out = []
    vroot = os.path.join(d, "Vulns")
    for r, _, fs in os.walk(vroot):
        low = os.path.basename(r).lower()
        if low.startswith("skip") or low.startswith("false"):
            continue
        for f in fs:
            if f.startswith("FIND-") and f.endswith(".md"):
                out.append(os.path.join(r, f))
    return sorted(out)


def section_nonempty(text, header_re):
    """True if a heading matching header_re exists with non-placeholder body."""
    lines = text.splitlines()
    for i, ln in enumerate(lines):
        if re.match(header_re, ln.strip(), re.I):
            body = []
            for nxt in lines[i + 1:]:
                if re.match(r"^#+\s", nxt):
                    break
                body.append(nxt)
            txt = "\n".join(body).strip()
            txt = re.sub(r"<[^>]+>", "", txt)  # drop <placeholder> angle tags
            return len(txt) >= 15
    return False


def lint_file(path):
    text = open(path, encoding="utf-8", errors="ignore").read()
    issues = []
    m = FNAME_RE.search(os.path.basename(path))
    sev = m.group(1).upper() if m else None
    if sev not in SEVERITIES:
        issues.append(f"bad/missing severity in filename ({sev})")
    for label, rx in REQUIRED.items():
        if not section_nonempty(text, rx):
            issues.append(f"missing/empty {label}")
    fm = re.search(r"^---\r?\n(.*?)\r?\n---", text, re.S)   # tolerate CRLF
    fmt = fm.group(1) if fm else ""
    if sev in ("CRITICAL", "HIGH"):
        # require a real CVSS v3 vector, not just the literal string "cvss:3" in prose
        blob = (fmt + "\n" + text).lower().replace(" ", "")
        if not re.search(r"av:[nalp]", blob):   # real vector token, not just the word "cvss" in prose
            issues.append("no CVSS vector (HIGH/CRITICAL should have an AV:... vector)")
    if re.search(r"^affected:\s*[\"']?\s*[\"']?\s*$", fmt, re.M):
        issues.append("empty 'affected' target")
    warnings = []
    band = cvss_band(cvss_score(fmt))
    if band and sev in SEVERITIES and band != sev:
        warnings.append(f"CVSS score maps to {band} but filename severity is {sev} "
                        f"(intentional? otherwise fix the label or the score)")
    if not re.search(r"^class:\s*\S", fmt, re.M):
        warnings.append("no `class:` set (canonical vuln class sharpens chain triggers + coverage)")
    return issues, warnings


def main():
    verbose = "-v" in sys.argv
    d = _engagement.active_dir()
    if not d:
        print("No active engagement.")
        return 0
    files = find_files(d)
    eng = os.path.basename(d)
    if not files:
        print(f"find-lint ({eng}): no FIND-*.md files yet.")
        return 0
    bad = 0
    for f in files:
        issues, warnings = lint_file(f)
        rel = os.path.relpath(f, d)
        if issues:
            bad += 1
            print(f"  FAIL {rel}")
            for i in issues:
                print(f"       - {i}")
        elif verbose:
            print(f"  ok   {rel}")
        for w in warnings:      # warnings print regardless of pass/fail, do not gate
            print(f"  WARN {rel}")
            print(f"       - {w}")
    print(f"\nfind-lint ({eng}): {len(files)-bad}/{len(files)} complete, {bad} need work.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
