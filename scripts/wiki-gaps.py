#!/usr/bin/env python3
"""wiki-gaps.py - list technique pages referenced but missing.

Scans hunt skills + FIND files for references to wiki technique pages that
have no backing file under wiki/. Prints one missing slug per line to stdout
(machine-readable for the SessionStart hook). Use -v for the referencing file.

Reference forms detected:
  - explicit path: wiki/techniques/<area>/<slug>.md   (anywhere)
  - wikilink:      [[slug]] or [[slug|alias]]          (hunt skills only)

Bare wikilinks in FIND files are NOT treated as gaps (they cross-ref findings,
hosts, etc.). Only explicit technique paths count there.
"""
import os
import re
import sys

# Self-locate so it works on any device (different user/path/spelling).
VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WIKI = os.path.join(VAULT, "wiki")
HUNT = os.path.join(VAULT, "skills", "hunt")
TARGETS = os.path.join(VAULT, "targets")

PATH_RE = re.compile(r"wiki/techniques/[\w./-]+?/([\w.-]+?)\.md")
LINK_RE = re.compile(r"\[\[([^\]|#]+?)(?:\|[^\]]*)?\]\]")
# valid page slug: kebab-case identifier. Filters payload strings, file refs, etc.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def existing_slugs():
    """Set of all .md basenames (no extension) anywhere under wiki/."""
    slugs = set()
    for root, _, files in os.walk(WIKI):
        for f in files:
            if f.endswith(".md"):
                slugs.add(f[:-3].lower())
    return slugs


def walk_md(base):
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(".md"):
                yield os.path.join(root, f)


def normalize(slug):
    # strip any leading path component from a wikilink target, lowercase
    s = slug.strip().split("/")[-1].lower()
    return s if SLUG_RE.match(s) else ""


def main():
    verbose = "-v" in sys.argv
    have = existing_slugs()
    gaps = {}  # slug -> referencing file (first seen)

    # hunt skills: both explicit paths and wikilinks
    for path in walk_md(HUNT):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in PATH_RE.findall(text):
            s = normalize(m)
            if s and s not in have:
                gaps.setdefault(s, path)
        for m in LINK_RE.findall(text):
            s = normalize(m)
            if s and s not in have:
                gaps.setdefault(s, path)

    # FIND files: explicit technique paths only
    for path in walk_md(TARGETS):
        text = open(path, encoding="utf-8", errors="ignore").read()
        for m in PATH_RE.findall(text):
            s = normalize(m)
            if s and s not in have:
                gaps.setdefault(s, path)

    for slug in sorted(gaps):
        if verbose:
            print(f"{slug}\t{os.path.relpath(gaps[slug], VAULT)}")
        else:
            print(slug)

    return 0


if __name__ == "__main__":
    sys.exit(main())
