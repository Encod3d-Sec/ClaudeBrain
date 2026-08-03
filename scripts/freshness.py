#!/usr/bin/env python3
"""Wiki freshness oracle: flag reuse-memory pages whose date_updated has aged past a
per-class threshold, so payload arsenals + reuse cheatsheets do not silently rot.

Reliable on /mnt/c: uses the date_updated FRONTMATTER, NOT filesystem mtime (the DrvFs
sync resets every file's mtime to the checkout date, so mtime cannot measure content
age here). Read-only signal; never edits a page.

  python3 scripts/freshness.py        # full report
  python3 scripts/freshness.py -q     # one-line stale count (SessionStart)
"""
import os
import re
import sys
from datetime import date

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WIKI = os.path.join(VAULT, "wiki")
# reuse-memory set: payload arsenals (all) + the row-structured reuse cheatsheets
TARGETS = [("payloads", None),
           ("cheatsheets", {"default-credentials", "api-request-findings", "cve-arsenal"})]
FAST = ("llm", "mcp", "cicd", "ai-", "prompt", "ml-model")   # fast-moving classes -> tighter window
FAST_DAYS = 90
SLOW_DAYS = 365
_DU = re.compile(r"^date_updated:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.M)
_DC = re.compile(r"^date_created:\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.M)


def _fm_date(text):
    m = _DU.search(text) or _DC.search(text)
    if not m:
        return None
    try:
        y, mo, d = map(int, m.group(1).split("-"))
        return date(y, mo, d)
    except ValueError:
        return None


def _fast(slug):
    return any(t in slug.lower() for t in FAST)


def _consider(dirpath, fn, slug, today, out):
    """Append (slug, date, age, threshold) to out if the page is past its window."""
    try:
        text = open(os.path.join(dirpath, fn), encoding="utf-8", errors="ignore").read()
    except OSError:
        return
    du = _fm_date(text)
    if not du:
        return
    thresh = FAST_DAYS if _fast(slug) else SLOW_DAYS
    age = (today - du).days
    if age > thresh:
        out.append((slug, du.isoformat(), age, thresh))


def stale(today=None):
    """List of (slug, date_updated, age_days, threshold_days) past their window."""
    today = today or date.today()
    out = []
    # flat reuse dirs: payload arsenals (all) + the designated reuse cheatsheets
    for sub, allow in TARGETS:
        d = os.path.join(WIKI, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".md"):
                continue
            slug = fn[:-3]
            if allow is not None and slug not in allow:
                continue
            _consider(d, fn, slug, today, out)
    # fast-moving TECHNIQUE pages (recursive; ONLY fast-class slugs, else the ~250
    # stable technique pages would flood the report). These rot fastest and were
    # previously unscanned, so the FAST window was effectively dead for techniques.
    troot = os.path.join(WIKI, "techniques")
    if os.path.isdir(troot):
        for r, _dirs, files in os.walk(troot):
            for fn in sorted(files):
                if fn.endswith(".md") and _fast(fn[:-3]):
                    _consider(r, fn, fn[:-3], today, out)
    out.sort(key=lambda r: r[2], reverse=True)
    return out


def main():
    rows = stale()
    if "-q" in sys.argv:
        if rows:
            print(f"Wiki freshness: {len(rows)} reuse page(s) past their refresh window "
                  f"(oldest {rows[0][0]} {rows[0][2]}d) - run scripts/freshness.py.")
        return 0
    if not rows:
        print("reuse-memory pages are within their refresh windows.")
        return 0
    print("Stale reuse pages (date_updated past per-class threshold):")
    for slug, du, age, thresh in rows:
        print(f"  {slug}: updated {du} ({age}d ago, window {thresh}d)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
