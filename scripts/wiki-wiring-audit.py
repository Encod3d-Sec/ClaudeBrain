#!/usr/bin/env python3
"""Audit which wiki technique/payload pages surface "by context" during an engagement.

A page is WIRED iff (see docs/superpowers/specs/2026-07-08-wiki-context-wiring-design.md):
  (a) its slug is in some scripts/playbook.json fingerprint's `refs`, OR
  (b) it is [[linked]] from any hunt-skill SKILL.md body, OR
  (c) it is [[linked]] from a page that satisfies (a) or (b)  -- ONE hop through an anchor/hub.

Full transitive closure is deliberately NOT used (the wiki is densely linked, so closure would call
everything "wired"). One hop through an anchor mirrors how a page actually reaches the model: a
fingerprint ref names it directly, or a loaded skill / surfaced hub page links it.

Pages listed in scripts/wiring-exempt.txt are excluded (index/overview/moc/course/meta pages).

Read-only. Usage:
  wiki-wiring-audit.py                 # human report, orphans grouped by domain + coverage %
  wiki-wiring-audit.py --json          # machine output for the CI gate / subagents
  wiki-wiring-audit.py --domain active-directory   # scope the orphan list to one domain dir
"""
from __future__ import annotations
import argparse, json, os, re, sys, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WIKI = os.path.join(ROOT, "wiki")
PLAYBOOK = os.path.join(ROOT, "scripts", "playbook.json")
SKILLS_GLOB = os.path.join(ROOT, "skills", "**", "*.md")  # all skills (hunt/, burp/, ...) wire pages via [[links]]
EXEMPT_FILE = os.path.join(ROOT, "scripts", "wiring-exempt.txt")

# Only these subtrees carry "should surface during an engagement" pages (gated by the CI test).
# tools/ and cheatsheets/ are audited separately (compute_tools / compute_cheats).
# DELIBERATELY NOT gated (verified by an over-look of the whole wiki/ tree, 2026-07-08):
#   - CTF/      : challenge writeups (passion-project content; user boundary = leave CTF alone)
#   - courses/  : course notes (personal reference, not engagement techniques)
#   - index.md  : auto-generated page catalog (meta)          -- scripts/gen_index.py
#   - moc.md    : global map-of-content / navigation hub (meta)
#   - overview.md: methodology-coverage map (meta)
# These are navigation/meta or explicitly out-of-scope, not attack techniques that fire by context.
AUDITED_SUBDIRS = ("techniques", "payloads")

WIKILINK = re.compile(r"\[\[([^\]|#]+)")
_FENCE_RE = re.compile(r"```.*?```", re.S)     # fenced code block
_INLINE_RE = re.compile(r"`[^`]*`")            # inline code span


def slug(path: str) -> str:
    return os.path.splitext(os.path.basename(path))[0]


def audited_pages() -> dict[str, list[str]]:
    """slug -> ALL paths sharing that slug, for every technique/payload page.

    Two files across different subtrees can share a basename (e.g. payloads/xss.md and
    techniques/web/xss.md - 20 such collisions exist in this wiki). A plain dict keyed by
    slug with direct assignment silently DROPS one of them from the audit entirely (never
    counted, never checked); list-valued entries keep every file visible.
    """
    out: dict[str, list[str]] = {}
    for sub in AUDITED_SUBDIRS:
        for f in glob.glob(os.path.join(WIKI, sub, "**", "*.md"), recursive=True):
            out.setdefault(slug(f), []).append(f)
    return out


def all_page_paths() -> dict[str, list[str]]:
    """slug -> ALL paths sharing that slug, for EVERY wiki page (hubs/moc may live outside
    audited subtrees). Used to expand one-hop links from an anchor: if two files share the
    anchor's slug, both sets of outbound links must be unioned, or the one whose links
    happen not to be picked first silently loses its one-hop propagation."""
    out: dict[str, list[str]] = {}
    for f in glob.glob(os.path.join(WIKI, "**", "*.md"), recursive=True):
        out.setdefault(slug(f), []).append(f)
    return out


def links_in(path: str) -> set[str]:
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return set()
    return {m.strip().lower() for m in WIKILINK.findall(text)}


def _rel_noext(path: str) -> str:
    """wiki-relative path without extension, forward-slashed, lowercased (matches a
    path-qualified [[link]] body, e.g. techniques/web/ssrf)."""
    rel = os.path.relpath(path, WIKI)
    return os.path.splitext(rel)[0].replace(os.sep, "/").lower()


def twin_pairs(pages: dict[str, list[str]]) -> list[tuple[str, str]]:
    """Intentional arsenal<->methodology twins: a basename shared by exactly one payloads/
    page and one techniques/ page. Data-driven (no hardcoded count); adapts as twins are
    added or removed."""
    out = []
    for _slug, paths in pages.items():
        pay = [p for p in paths if os.path.relpath(p, WIKI).startswith("payloads" + os.sep)]
        tech = [p for p in paths if os.path.relpath(p, WIKI).startswith("techniques" + os.sep)]
        if len(pay) == 1 and len(tech) == 1:
            out.append((pay[0], tech[0]))
    return out


def links_outside_fences(path: str) -> set[str]:
    """Like links_in(), but ignores [[links]] inside fenced or inline code. A wikilink buried in
    a code block renders as literal text in Obsidian (not a functional link), so it must NOT count
    toward the twin mutual-link requirement."""
    try:
        text = open(path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return set()
    text = _INLINE_RE.sub("", _FENCE_RE.sub("", text))
    return {m.strip().lower() for m in WIKILINK.findall(text)}


def twin_link_violations(pages: dict[str, list[str]]) -> list[dict]:
    """Each twin pair must be MUTUALLY cross-linked with a PATH-QUALIFIED [[link]] (a bare
    [[slug]] is ambiguous between the twins and does not count). A link inside a code fence does
    not count (not a functional link). Returns one record per missing direction."""
    bad = []
    for pay, tech in twin_pairs(pages):
        pay_links = links_outside_fences(pay)
        tech_links = links_outside_fences(tech)
        if _rel_noext(tech) not in pay_links:
            bad.append({"file": os.path.relpath(pay, ROOT), "missing_link": _rel_noext(tech),
                        "direction": "payload->technique"})
        if _rel_noext(pay) not in tech_links:
            bad.append({"file": os.path.relpath(tech, ROOT), "missing_link": _rel_noext(pay),
                        "direction": "technique->payload"})
    return bad


def playbook_refs() -> set[str]:
    d = json.load(open(PLAYBOOK, encoding="utf-8"))
    refs = set()
    for v in d["fingerprints"].values():
        for r in v.get("refs", []):
            refs.add(r.replace("payloads/", "").strip().lower())
    return refs


def playbook_tools() -> set[str]:
    d = json.load(open(PLAYBOOK, encoding="utf-8"))
    out = set()
    for v in d["fingerprints"].values():
        for t in v.get("tools", []):
            out.add(t.replace("tools/", "").strip().lower())
    return out


def tool_pages() -> dict[str, str]:
    return {slug(f): f for f in glob.glob(os.path.join(WIKI, "tools", "*.md"))}


def cheat_pages() -> dict[str, str]:
    return {slug(f): f for f in glob.glob(os.path.join(WIKI, "cheatsheets", "*.md"))}


def skill_body_links() -> set[str]:
    out = set()
    for f in glob.glob(SKILLS_GLOB, recursive=True):
        out |= links_in(f)
    return out


def load_exempt() -> set[str]:
    if not os.path.exists(EXEMPT_FILE):
        return set()
    out = set()
    for line in open(EXEMPT_FILE, encoding="utf-8"):
        line = line.split("#", 1)[0].strip().lower()
        if line:
            out.add(line)
    return out


def _one_hop(anchors: set[str], everypath: dict[str, list[str]]) -> set[str]:
    """Tier (c): slugs linked FROM an anchor page (the hub lists its children). An anchor slug
    may match more than one file (duplicate basename across subtrees), so union the links from
    ALL of them, not just whichever glob() returned first. Shared by the page, tool, and
    cheatsheet audits so all three honour the same tier (c) the module docstring describes."""
    out: set[str] = set()
    for a in anchors:
        for p in everypath.get(a, []):
            out |= links_in(p)
    return out


def compute():
    pages = audited_pages()
    everypath = all_page_paths()
    exempt = load_exempt()

    # Tier (a) + (b): direct anchors. Tier (c): one hop through an anchor page.
    anchors = playbook_refs() | skill_body_links()
    wired = anchors | _one_hop(anchors, everypath)
    # Orphan status is per-SLUG (the unit a [[wikilink]]/playbook ref names): if a slug resolves
    # to more than one file, either file being wired counts as the slug being wired, since a
    # link to the bare slug cannot distinguish which twin was intended.
    orphans = sorted(s for s in pages if s not in wired and s not in exempt)
    return pages, wired, exempt, orphans, anchors


def compute_tools():
    tools = tool_pages()
    exempt = load_exempt()
    # A tool is wired if a fingerprint recommends it (tools/refs), a hunt skill links it, or it
    # is one hop from such an anchor (linked by an anchor wiki page). Same tier (c) as the page
    # audit, so a tool referenced from an anchor cheatsheet/technique page counts as reachable.
    anchors = playbook_tools() | playbook_refs() | skill_body_links()
    wired = anchors | _one_hop(anchors, all_page_paths())
    orphans = sorted(s for s in tools if s not in wired and s not in exempt)
    return tools, orphans, anchors


def compute_cheats():
    cheats = cheat_pages()
    exempt = load_exempt()
    anchors = playbook_tools() | playbook_refs() | skill_body_links()
    wired = anchors | _one_hop(anchors, all_page_paths())
    orphans = sorted(s for s in cheats if s not in wired and s not in exempt)
    return cheats, orphans, anchors


def domain_of(path: str) -> str:
    rel = os.path.relpath(path, WIKI)
    parts = rel.split(os.sep)
    # techniques/<domain>/... -> domain ; payloads/x.md -> payloads
    if parts[0] == "techniques" and len(parts) > 2:
        return f"techniques/{parts[1]}"
    return parts[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--domain", help="filter orphan list to this domain dir (e.g. techniques/active-directory)")
    args = ap.parse_args()

    pages, wired, exempt, orphans, anchors = compute()
    tools, tool_orphans, _ = compute_tools()
    cheats, cheat_orphans, _ = compute_cheats()

    # duplicate-slug diagnostic: surfaced so a future collision doesn't silently hide a page again
    dupes = {s: paths for s, paths in pages.items() if len(paths) > 1}
    twin_viol = twin_link_violations(pages)

    by_dom: dict[str, list[str]] = {}
    for s in orphans:
        dom = domain_of(pages[s][0])
        if args.domain and args.domain not in dom:
            continue
        by_dom.setdefault(dom, []).append(s)

    total = sum(len(v) for v in pages.values())  # count FILES, not unique slugs
    wired_n = sum(len(v) for s, v in pages.items() if s in wired or s in exempt)
    cov = 100.0 * wired_n / total if total else 100.0

    tcov = 100.0 * (len(tools) - len(tool_orphans)) / len(tools) if tools else 100.0

    if args.json:
        print(json.dumps({
            "total": total, "wired_or_exempt": wired_n, "coverage_pct": round(cov, 1),
            "orphans": [{"slug": s, "domain": domain_of(pages[s][0]), "path": os.path.relpath(pages[s][0], ROOT)}
                        for s in orphans if (not args.domain) or args.domain in domain_of(pages[s][0])],
            "anchors": sorted(a for a in anchors),
            "duplicate_slugs": {s: [os.path.relpath(p, ROOT) for p in paths] for s, paths in dupes.items()},
            "twin_link_violations": twin_viol,
            "tools_total": len(tools), "tools_coverage_pct": round(tcov, 1), "tool_orphans": tool_orphans,
            "cheats_total": len(cheats), "cheat_orphans": cheat_orphans,
        }, indent=2))
        return

    ccov = 100.0 * (len(cheats) - len(cheat_orphans)) / len(cheats) if cheats else 100.0
    print(f"Wiki wiring coverage: {wired_n}/{total} = {cov:.1f}%  ({len(orphans)} orphaned)")
    print(f"Tool coverage: {len(tools) - len(tool_orphans)}/{len(tools)} = {tcov:.1f}%  ({len(tool_orphans)} tools not recommended by any context)")
    print(f"Cheatsheet coverage: {len(cheats) - len(cheat_orphans)}/{len(cheats)} = {ccov:.1f}%  ({len(cheat_orphans)} not surfaced)")
    print(f"(anchors: {len(anchors)}  exempt: {len(exempt)})")
    if tool_orphans:
        print("  unwired tools:", ", ".join(tool_orphans))
    if cheat_orphans:
        print("  unwired cheatsheets:", ", ".join(cheat_orphans))
    if dupes:
        print(f"  duplicate slugs ({len(dupes)}, both files audited independently):", ", ".join(sorted(dupes)))
    if twin_viol:
        print(f"  twin cross-link gaps ({len(twin_viol)}): payload<->technique pairs not mutually [[linked]]")
        for v in twin_viol:
            print(f"    {v['file']} missing [[{v['missing_link']}]] ({v['direction']})")
    print("-" * 70)
    for dom in sorted(by_dom):
        print(f"\n### {dom}  ({len(by_dom[dom])} orphaned)")
        for s in by_dom[dom]:
            print(f"  {s}")


if __name__ == "__main__":
    main()
