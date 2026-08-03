#!/usr/bin/env python3
"""Generate a deduplicated findings index for an engagement tree.

A programme that moves findings through lifecycle folders ends up with the SAME finding
copied several times (a reports folder, a submitted folder, a tested folder, an
out-of-scope folder...). Counting files then overstates the real finding count, and it is
easy to edit a stale copy. This walks the tree, collapses copies, and prints a markdown
table linking the canonical one.

    python3 scripts/gen-findings-index.py <engagement-dir> [--priority "1. Submitted,0. Reports"]

Prints markdown to stdout; redirect or paste it into the engagement's hub file.
Canonical copy = the one in the highest-priority lifecycle folder (order configurable).
Duplicates are reported as "+N copies" rather than silently dropped.
"""
import argparse
import collections
import os
import re
import sys

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
DEFAULT_PRIORITY = [
    "1. Submitted", "0. Reports", "3. TESTED", "4. REDO",
    "2. DEAD", "5. PDF", "6. TODO", "7. OutOfScope",
]


def field(text, name):
    m = re.search(r"^%s:\s*(.*)$" % name, text, re.M)
    return m.group(1).strip().strip('"') if m else ""


def collect(root):
    rows = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not (fn.startswith("FIND-") and fn.endswith(".md")):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                text = open(full, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            rows.append({
                "path": rel.replace(os.sep, "/"),
                "fn": fn,
                "sev": field(text, "severity").upper(),
                "status": field(text, "status"),
                "title": field(text, "title"),
            })
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("engagement_dir")
    ap.add_argument("--priority", default=",".join(DEFAULT_PRIORITY),
                    help="comma-separated lifecycle folder names, most canonical first")
    args = ap.parse_args()

    root = args.engagement_dir
    if not os.path.isdir(root):
        print("gen-findings-index: not a directory: %s" % root, file=sys.stderr)
        return 2
    priority = [p.strip() for p in args.priority.split(",") if p.strip()]

    rows = collect(root)
    if not rows:
        print("gen-findings-index: no FIND-*.md under %s" % root, file=sys.stderr)
        return 1

    def bucket(path):
        for i, pre in enumerate(priority):
            if path.startswith(pre + "/"):
                return i
        return len(priority)

    # Group copies: same filename slug (minus the FIND-NNN- prefix and a trailing " 1"
    # duplicate marker) plus the same title prefix means the same finding.
    groups = collections.defaultdict(list)
    for r in rows:
        slug = re.sub(r"^FIND-\d+-", "", r["fn"]).replace(" 1.md", ".md")
        groups[(slug, r["title"][:60])].append(r)

    canon = []
    for copies in groups.values():
        copies.sort(key=lambda r: bucket(r["path"]))
        best = dict(copies[0])
        best["dupes"] = len(copies) - 1
        canon.append(best)

    def sev_index(r):
        for i, k in enumerate(SEV_ORDER):
            if r["sev"].startswith(k):
                return i
        return len(SEV_ORDER)

    canon.sort(key=lambda r: (sev_index(r), r["path"]))

    def flag(r):
        st = (r["status"] + " " + r["sev"]).upper()
        if "DISPROVEN" in st:
            return " **DO NOT SUBMIT - DISPROVEN**"
        if "SUPERSEDED" in st:
            return " *(superseded)*"
        return ""

    counts = collections.Counter()
    current = None
    out = []
    for r in canon:
        head = next((k for k in SEV_ORDER if r["sev"].startswith(k)), "OTHER")
        counts[head] += 1
        if head != current:
            current = head
            out.append("\n### %s\n" % head)
            out.append("| Finding | Host / area | Status |")
            out.append("|---|---|---|")
        top = r["path"].split("/")[0]
        rest = r["path"][len(top) + 1:]
        host = rest.split("/")[0] if top in priority and "/" in rest else top
        dup = " +%d copies" % r["dupes"] if r["dupes"] else ""
        status = r["status"] if len(r["status"]) < 40 else r["status"][:37] + "..."
        out.append("| [[%s\\|%s]]%s | %s%s | %s |"
                   % (r["path"], r["fn"][:-3], flag(r), host, dup, status))

    print("\n".join(out))
    print("\n<!-- %d unique findings from %d files: %s -->"
          % (len(canon), len(rows),
             ", ".join("%s %d" % (k, counts[k]) for k in SEV_ORDER if counts[k])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
