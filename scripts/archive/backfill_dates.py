#!/usr/bin/env python3
"""One-time: backfill date_created/date_updated frontmatter on wiki pages that
lack any date, using the file mtime. Skips auto-generated pages. Idempotent
(only touches pages with neither date field). Kept in scripts/archive/ as a record.

    python3 scripts/archive/backfill_dates.py [--dry-run]
"""
import datetime
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
WIKI = os.path.join(VAULT, "wiki")
FM_RE = re.compile(r"^---\n(.*?)\n---", re.S)
GENERATED = {"index.md", "moc.md", "overview.md"}


def is_generated(name):
    return name in GENERATED or name.endswith("-moc.md")


def main():
    dry = "--dry-run" in sys.argv
    changed = 0
    for root, _, files in os.walk(WIKI):
        for f in files:
            if not f.endswith(".md") or is_generated(f):
                continue
            path = os.path.join(root, f)
            text = open(path, encoding="utf-8", errors="ignore").read()
            m = FM_RE.match(text)
            if not m:
                continue
            body = m.group(1)
            if "date_created" in body or "date_updated" in body:
                continue
            d = datetime.date.fromtimestamp(os.path.getmtime(path)).isoformat()
            insert = f"date_created: {d}\ndate_updated: {d}\n"
            # insert immediately before the closing --- of the frontmatter block
            new = text[:m.end(1)] + "\n" + insert.rstrip("\n") + text[m.end(1):]
            rel = os.path.relpath(path, VAULT)
            print(f"{'would set' if dry else 'set'} {d}  {rel}")
            if not dry:
                open(path, "w", encoding="utf-8").write(new)
            changed += 1
    print(f"\n{'would backfill' if dry else 'backfilled'} {changed} page(s)")


if __name__ == "__main__":
    main()
