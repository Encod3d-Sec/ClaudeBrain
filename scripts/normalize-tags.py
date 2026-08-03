#!/usr/bin/env python3
"""normalize-tags.py - apply the controlled tag vocabulary to wiki pages.

Per page: alias-merge synonyms, drop vague tags + uncurated singletons, dedup,
sort. Keeps a tag if (after aliasing) it is in vocab 'keep' or its corpus count
>= threshold, and not in 'drop'. Excludes CTF and courses (left untouched).

  python3 scripts/normalize-tags.py          # dry-run (default): show changes
  python3 scripts/normalize-tags.py --apply   # write changes

Idempotent. Tags-line format expected: `tags: [a, b, c]` (single line).
"""
import json
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WIKI = os.path.join(VAULT, "wiki")
VOCAB = json.load(open(os.path.join(VAULT, "scripts", "tag-vocab.json"), encoding="utf-8"))
ALIASES = {k.lower(): v.lower() for k, v in VOCAB["aliases"].items()}
KEEP = {t.lower() for t in VOCAB["keep"]}
DROP = {t.lower() for t in VOCAB["drop"]}
KEEP_PATTERNS = [re.compile(p) for p in VOCAB.get("keep_patterns", [])]
THRESHOLD = VOCAB.get("threshold", 3)
EXCLUDE = (os.sep + "CTF", os.sep + "courses")
TAGS_RE = re.compile(r"^(tags:\s*)\[(.*?)\]\s*$", re.M)


def pages():
    for r, _, fs in os.walk(WIKI):
        if any(x in r + os.sep for x in EXCLUDE):
            continue
        for f in fs:
            if not f.endswith(".md"):
                continue
            if f in ("index.md", "moc.md", "overview.md") or f.endswith("-moc.md"):
                continue   # generated pages: gen_index/build_moc own their tags, don't fight them
            yield os.path.join(r, f)


def parse_tags(text):
    m = TAGS_RE.search(text)
    if not m:
        return None, None
    raw = [x.strip().strip('"\'').lower() for x in m.group(2).split(",") if x.strip()]
    return raw, m


def alias(tag):
    return ALIASES.get(tag, tag)


def main():
    apply = "--apply" in sys.argv
    # pass 1: corpus counts after aliasing
    counts = {}
    page_tags = {}
    for p in pages():
        raw, m = parse_tags(open(p, encoding="utf-8", errors="ignore").read())
        if raw is None:
            continue
        aliased = [alias(t) for t in raw]
        page_tags[p] = (raw, aliased)
        for t in set(aliased):
            counts[t] = counts.get(t, 0) + 1

    keep_set = set(KEEP) | {t for t, c in counts.items() if c >= THRESHOLD}
    keep_set -= DROP

    def keepable(t):
        if t in DROP:
            return False
        return t in keep_set or any(p.match(t) for p in KEEP_PATTERNS)

    changed = 0
    removed_total = 0
    before_uniq = set()
    after_uniq = set()
    for p, (raw, aliased) in page_tags.items():
        before_uniq |= set(raw)
        new = []
        for t in aliased:
            if keepable(t) and t not in new:
                new.append(t)
        new.sort()
        after_uniq |= set(new)
        if new == raw:
            continue
        changed += 1
        removed_total += len([t for t in raw if not keepable(alias(t))])
        rel = os.path.relpath(p, WIKI)
        dropped = sorted(set(raw) - set(new))
        merged = sorted({f"{t}->{alias(t)}" for t in raw if alias(t) != t and alias(t) in new})
        note = []
        if dropped:
            note.append("drop " + ",".join(dropped))
        if merged:
            note.append("merge " + ",".join(merged))
        print(f"  {rel}: {'; '.join(note)}")
        if apply:
            text = open(p, encoding="utf-8", errors="ignore").read()
            text = TAGS_RE.sub(lambda m: f"{m.group(1)}[{', '.join(new)}]", text, count=1)
            open(p, "w", encoding="utf-8").write(text)

    print(f"\n{'APPLIED' if apply else 'DRY-RUN'}: {changed} pages change, "
          f"~{removed_total} tag instances removed.")
    print(f"unique tags: {len(before_uniq)} -> {len(after_uniq)}")
    if not apply:
        print("re-run with --apply to write.")


if __name__ == "__main__":
    main()
