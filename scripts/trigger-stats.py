#!/usr/bin/env python3
"""Hunt-trigger fire telemetry stats.

Reads <vault>/.trigger-fire.jsonl (written by skills/hooks/hunt-trigger.py on
every UserPromptSubmit) and prints the match rate plus per-skill fire counts.
Use it to tune skills/hunt/triggers.json: raise the hit rate, spot over-firing.

Leak-safe: the log holds NO prompt text -- only timestamps, fired skill lists,
and prompt length -- so it is safe to read and share. The file is gitignored.

Run: python3 scripts/trigger-stats.py [--recent N]
  --recent N   only the last N records (default: all)
"""
import json
import os
import sys
from collections import Counter

VAULT = os.environ.get("CLAUDEBRAIN_VAULT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
LOG = os.path.join(VAULT, ".trigger-fire.jsonl")


def _pct(n, total):
    return (100 * n // total) if total else 0


def main():
    recent = None
    if "--recent" in sys.argv:
        try:
            recent = int(sys.argv[sys.argv.index("--recent") + 1])
        except (ValueError, IndexError):
            print("usage: trigger-stats.py [--recent N]")
            return

    if not os.path.isfile(LOG):
        print("no telemetry yet: %s" % LOG)
        print("(the hunt-trigger UserPromptSubmit hook writes it on each prompt)")
        return

    rows = []
    for line in open(LOG, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    if recent:
        rows = rows[-recent:]

    total = len(rows)
    if not total:
        print("log empty")
        return

    hard_n = soft_n = miss = 0
    skills = Counter()
    for r in rows:
        h, s = r.get("hard") or [], r.get("soft") or []
        if h:
            hard_n += 1
        elif s:
            soft_n += 1
        else:
            miss += 1
        for sk in h + s:
            skills[sk] += 1

    fired = hard_n + soft_n
    print("prompts logged : %d%s" % (total, (" (last %d)" % recent) if recent else ""))
    print("fired (any)    : %d  (%d%%)" % (fired, _pct(fired, total)))
    print("  hard trigger : %d  (%d%%)" % (hard_n, _pct(hard_n, total)))
    print("  surface only : %d  (%d%%)" % (soft_n, _pct(soft_n, total)))
    print("missed         : %d  (%d%%)" % (miss, _pct(miss, total)))
    if skills:
        print("\ntop skills fired:")
        for sk, c in skills.most_common(15):
            print("  %4d  %s" % (c, sk))
    print("\nHigh miss rate during hunting -> add the missed surface terms to")
    print("skills/hunt/triggers.json (surface_triggers). Over-firing -> tighten a pattern.")


if __name__ == "__main__":
    main()
