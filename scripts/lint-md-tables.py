#!/usr/bin/env python3
"""Markdown (GFM) table-integrity linter.

Flags the two malformations that silently break tables in engagement files -- both
observed live on a password-audit box, where nothing caught them:

  1. column-count mismatch: a data row whose cell count differs from its header
     (also fires when an unescaped `|` inside a pasted payload/`<script>` splits a
     cell, which is the "<script> breaks the table" case), and
  2. blank-line split: a table body detached from its header/separator by a blank
     line, which renders as two broken blocks instead of one table.

Advisory. Run on an engagement dir or a wiki page:

    python3 scripts/lint-md-tables.py targets/<eng>/          # recurse *.md
    python3 scripts/lint-md-tables.py wiki/cheatsheets/x.md   # one file
    python3 scripts/lint-md-tables.py -q targets/<eng>/       # exit code only

Exit 1 if any issue is found (0 when clean), so it doubles as a gate.
`lint_paths()` is imported by engagement-init.py for a SessionStart warning.
"""
import os
import re
import sys

_SEP_RE = re.compile(r"^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$")


def _is_row(line):
    s = line.strip()
    return s.startswith("|") and s.count("|") >= 2


def _is_sep(line):
    return _is_row(line) and "-" in line and _SEP_RE.match(line) is not None


def _cells(line):
    """Cell count of a GFM row, tolerant of optional edge pipes and escaped \\|."""
    s = line.strip()
    s = s[1:] if s.startswith("|") else s
    s = s[:-1] if s.endswith("|") else s
    return len(re.split(r"(?<!\\)\|", s))


def lint_text(text):
    """Return [(line_no, message), ...] for one document's malformed tables."""
    issues = []
    lines = text.split("\n")
    n = len(lines)
    i = 0
    while i < n:
        if _is_row(lines[i]) and i + 1 < n and _is_sep(lines[i + 1]):
            header = _cells(lines[i])
            j = i + 2
            while j < n and _is_row(lines[j]) and not _is_sep(lines[j]):
                if _cells(lines[j]) != header:
                    issues.append((j + 1, "row has %d cells, header has %d"
                                   % (_cells(lines[j]), header)))
                j += 1
            k = j
            while k < n and lines[k].strip() == "":
                k += 1
            # a table row after blank line(s) that is NOT the header of a new table
            if k > j and k < n and _is_row(lines[k]) and not (
                    k + 1 < n and _is_sep(lines[k + 1])):
                issues.append((k + 1, "table row detached from its header by a "
                               "blank line (renders as a broken block)"))
            i = max(j, i + 1)
        else:
            i += 1
    return issues


def lint_file(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return []
    return [(path, ln, msg) for ln, msg in lint_text(text)]


def lint_paths(paths):
    """Flatten file/dir paths to [(path, line, msg), ...]; dirs recurse *.md."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    if fn.endswith(".md"):
                        out.extend(lint_file(os.path.join(root, fn)))
        elif p.endswith(".md"):
            out.extend(lint_file(p))
    return out


def demo():
    bad_cols = "| a | b |\n|---|---|\n| 1 | 2 | 3 |\n"
    assert lint_text(bad_cols), "should flag a 3-cell row under a 2-cell header"
    split = "| a | b |\n|---|---|\n\n| 1 | 2 |\n"
    assert any("detached" in m for _, m in lint_text(split)), "should flag blank-split body"
    clean = "| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n"
    assert not lint_text(clean), "clean table must pass"
    print("lint-md-tables self-check ok")


def main(argv):
    args = [a for a in argv if a != "-q"]
    quiet = "-q" in argv
    if not args:
        demo()
        return 0
    issues = lint_paths(args)
    if issues and not quiet:
        for path, ln, msg in issues:
            print("%s:%d: %s" % (path, ln, msg))
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
