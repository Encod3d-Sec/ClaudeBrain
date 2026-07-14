#!/usr/bin/env python3
"""coverage.py - show per-asset vuln-class coverage gaps for the active engagement.

applicable(asset) = base classes for the engagement type + classes implied by any
matched playbook fingerprint (tech). gaps = applicable - tested. `tested` is
auto-credited from the files the discipline already produces (explicit coverage.md
rows + written findings + Deadends.md), so the gap list stays current without manual
bookkeeping. Surfaces what is in scope but not yet tested, so thoroughness is systematic.

  python3 scripts/coverage.py        # gaps per asset
  python3 scripts/coverage.py -v     # also show tested + applicable
"""
import json
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement  # noqa: E402

CLASSES = json.load(open(os.path.join(VAULT, "scripts", "coverage-classes.json"),
                        encoding="utf-8"))
try:
    PLAYBOOK = json.load(open(os.path.join(VAULT, "scripts", "playbook.json"),
                              encoding="utf-8"))["fingerprints"]
except FileNotFoundError:
    PLAYBOOK = {}   # absent -> silent
except Exception as _e:
    PLAYBOOK = {}
    sys.stderr.write(f"coverage: playbook.json unreadable ({_e}); implied classes disabled\n")
_CLEAN_CLASS = re.compile(r"^[a-z0-9][a-z0-9 ._-]*$", re.I)


def fingerprint_classes(blob):
    out = []
    for pat in PLAYBOOK:
        try:
            if not re.search(pat, blob):
                continue
        except re.error:
            continue
        cls = pat.split("|")[0].strip().replace("\\b", "").replace("\\", "")
        if cls and _CLEAN_CLASS.match(cls):   # skip regex-metachar garbage -> no phantom class
            out.append(cls)
    return out


def gaps():
    d = _engagement.active_dir()
    if not d:
        return None, []
    etype = _engagement.engagement_type(d)
    sc = _engagement.scope(d)
    base = CLASSES.get(etype, [])
    state = _engagement._parse_table(os.path.join(d, "state.md"))
    # tested = explicit coverage.md + auto-credit from findings & Deadends (self-maintaining)
    per_asset, glob = _engagement.tested_classes(d, etype, base)

    def entity(r):
        return _engagement.entity(r, etype)

    rows = []
    for r in state:
        ent = entity(r)
        if ent == "?" or _engagement.out_of_scope_match(ent, sc):
            continue
        blob = " ".join(str(r.get(k, "")) for k in
                        ("tech", "services", "service", "os", "notes")).lower()
        applicable = list(dict.fromkeys(base + fingerprint_classes(blob)))
        tested = {t.lower() for t in per_asset.get(ent.lower(), set()) | glob}
        g = [c for c in applicable if c.lower() not in tested]
        rows.append((ent, g, sorted(tested), applicable))
    return etype, rows


def main():
    verbose = "-v" in sys.argv
    _engagement.ensure_optional_file("coverage")   # a coverage check counts as "runs" -> back-fill on a lean ctf room
    etype, rows = gaps()
    if etype is None:
        print("No active engagement.")
        return
    print(f"Coverage gaps ({_engagement.active_dir().split('/')[-1]}, {etype}):")
    if not rows:
        print("  no in-scope assets in state.md yet.")
    for ent, g, tested, app in rows:
        if g:
            print(f"  {ent}: untested {', '.join(g)}")
        else:
            print(f"  {ent}: complete ({len(tested)}/{len(app)})")
        if verbose:
            print(f"     tested[{', '.join(tested) or '-'}] applicable[{', '.join(app)}]")


if __name__ == "__main__":
    main()
