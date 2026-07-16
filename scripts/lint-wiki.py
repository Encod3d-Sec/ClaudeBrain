#!/usr/bin/env python3
"""lint-wiki.py - integrity check for the wiki + framework docs.

Catches the drift classes that silently break autonomy:
  1. broken wikilinks   - [[target]] with no backing page (code blocks ignored)
  2. dead script refs   - docs/CLAUDE.md/skills reference scripts/* that do not exist
  3. frontmatter health - wiki pages missing tags or a date
  4. index staleness    - wiki/index.md out of sync with gen_index.py
  5. lean areas         - technique areas with the least content (informational)

Exit status:
  0 = clean (lean-area notes do not fail)
  1 = one or more hard problems (links / dead refs / frontmatter / stale index)

  python3 scripts/lint-wiki.py          # full human report
  python3 scripts/lint-wiki.py -q       # one-line summary (SessionStart hook)
  python3 scripts/lint-wiki.py -v       # verbose: list every offender
"""
import json
import os
import re
import subprocess
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WIKI = os.path.join(VAULT, "wiki")

FENCE_RE = re.compile(r"```.*?```", re.S)
INLINE_RE = re.compile(r"`[^`]*`")
LINK_RE = re.compile(r"\[\[([^\]]+?)\]\]")
SCRIPTREF_RE = re.compile(r"scripts/([A-Za-z0-9_.-]+\.(?:py|sh))")
# markdown image ![alt](url) or obsidian embed ![[file]] - both banned in wiki pages
IMG_RE = re.compile(r"!\[[^\]]*\]\([^)]+\)|!\[\[[^\]]+\]\]")
# the auto-generated Tools-section stub that ~38% of pages still ship (a TODO, not a link);
# lint ignores it as a "broken link" because it sits in backticks, so it accumulates unseen
PLACEHOLDER_TOOL = "[[tool]]"
FM_RE = re.compile(r"^---\r?\n(.*?)\r?\n---", re.S)   # tolerate CRLF (this vault lives on /mnt/c)
# external/meta link targets that are valid without a backing wiki page
EXTERNAL_OK = {"moc", "index", "overview"}
# auto-generated pages (gen_index.py / build_moc.py) - excluded from authored-content
# checks (frontmatter date, em-dash) since their content is not hand-written
GENERATED = {"index.md", "moc.md", "overview.md", "README.md"}


def is_generated(path):
    b = os.path.basename(path)
    return b in GENERATED or b.endswith("-moc.md")


def wiki_md(skip_generated=False):
    for root, _, files in os.walk(WIKI):
        for f in files:
            if f.endswith(".md"):
                p = os.path.join(root, f)
                if skip_generated and is_generated(p):
                    continue
                yield p


def existing_basenames():
    return {os.path.basename(p)[:-3].lower() for p in wiki_md()}


def link_target(raw):
    """Normalize a [[...]] body to its resolvable basename slug."""
    s = raw.split("|")[0].split("#")[0].strip()  # drop alias + heading anchor
    s = s.split("/")[-1].lower()                   # drop any path component
    return s


def check_broken_links(have):
    """Return list of (target, referencing_file) for unresolved wikilinks."""
    bad = []
    valid = have | EXTERNAL_OK
    for path in wiki_md():
        text = open(path, encoding="utf-8", errors="ignore").read()
        text = FENCE_RE.sub("", text)   # drop fenced code (bash [[ ]], heredocs)
        text = INLINE_RE.sub("", text)  # drop inline code
        for m in LINK_RE.findall(text):
            t = link_target(m)
            # only kebab/word slugs are real page links; skip junk fragments
            if not t or not re.match(r"^[a-z0-9][a-z0-9-]*$", t):
                continue
            if t not in valid:
                bad.append((t, os.path.relpath(path, VAULT)))
    return bad


def check_dead_scriptrefs():
    """Return list of (scriptname, referencing_file) for scripts/* that do not exist."""
    bad = []
    roots = [os.path.join(VAULT, "docs"), os.path.join(VAULT, "skills"),
             os.path.join(VAULT, "CLAUDE.md")]
    files = []
    for r in roots:
        if os.path.isfile(r):
            files.append(r)
        elif os.path.isdir(r):
            for dp, dirs, fs in os.walk(r):
                # docs/superpowers/ is the gitignored planning workspace: specs/plans name
                # scripts they propose to DELETE, so they legitimately reference removed
                # scripts. Skip it so the dead-ref check reflects only shipping references.
                dirs[:] = [d for d in dirs if d != "superpowers"]
                files += [os.path.join(dp, f) for f in fs if f.endswith((".md", ".py", ".sh"))]
    for path in files:
        text = open(path, encoding="utf-8", errors="ignore").read()
        for name in set(SCRIPTREF_RE.findall(text)):
            if not os.path.exists(os.path.join(VAULT, "scripts", name)):
                bad.append((name, os.path.relpath(path, VAULT)))
    return bad


def _skill_exists(repo, name):
    """True if name resolves to skills/hunt/<name> or skills/<name>."""
    return (os.path.isdir(os.path.join(repo, "skills", "hunt", name))
            or os.path.isdir(os.path.join(repo, "skills", name)))


def check_playbook(have, repo):
    """Verify scripts/playbook.json integrity (fail-open). Returns HARD findings.

    - fingerprint keys must compile as a regex (next_move silently drops bad ones)
    - every 'refs' entry must resolve to a wiki page basename (post-'/' slug)
    - every 'skills' entry must resolve to a real skill dir
    A missing/garbled playbook.json is reported once, never raised.
    """
    bad = []
    path = os.path.join(repo, "scripts", "playbook.json")
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
        fps = data["fingerprints"]
    except Exception as e:
        return [("scripts/playbook.json", f"unreadable: {e}")]
    for key, fp in fps.items():
        try:
            re.compile(key, re.I)
        except re.error as e:
            bad.append((f"playbook fingerprint [{key}]", f"bad regex: {e}"))
        if not isinstance(fp, dict):
            continue
        for ref in fp.get("refs", []):
            slug = ref.split("/")[-1].lower()
            if slug not in have:
                bad.append((f"playbook [{key}]", f"unresolved ref: {ref}"))
        for sk in fp.get("skills", []):
            if not _skill_exists(repo, sk):
                bad.append((f"playbook [{key}]", f"missing skill: {sk}"))
    return bad


def check_triggers(repo):
    """Verify every triggers.json + surface_triggers target resolves to a skill.

    Fail-open: a missing/garbled triggers.json is reported once, never raised.
    """
    bad = []
    path = os.path.join(repo, "skills", "hunt", "triggers.json")
    try:
        data = json.load(open(path, encoding="utf-8", errors="ignore"))
    except Exception as e:
        return [("skills/hunt/triggers.json", f"unreadable: {e}")]
    for section in ("triggers", "surface_triggers"):
        for key, val in data.get(section, {}).items():
            targets = val if isinstance(val, list) else [val]
            for sk in targets:
                if not _skill_exists(repo, sk):
                    bad.append((f"{section} [{key}]", f"missing skill: {sk}"))
    return bad


def check_frontmatter():
    """Return (hard, soft): hard = no frontmatter / no tags; soft = no date."""
    hard, soft = [], []
    for path in wiki_md(skip_generated=True):
        text = open(path, encoding="utf-8", errors="ignore").read()
        m = FM_RE.match(text)
        rel = os.path.relpath(path, VAULT)
        if not m:
            hard.append((rel, "no frontmatter"))
            continue
        body = m.group(1)
        if "tags:" not in body:
            hard.append((rel, "no tags"))
        if "date_updated" not in body and "date_created" not in body:
            soft.append((rel, "no date"))
    return hard, soft


def check_index_stale():
    """True if wiki/index.md differs from gen_index.py output."""
    try:
        r = subprocess.run(
            ["python3", os.path.join(VAULT, "scripts", "gen_index.py"), "--check"],
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode != 0
    except Exception:
        return False


def lean_areas(n=3):
    """Return [(area, total_lines)] for the n leanest technique areas (informational)."""
    tech = os.path.join(WIKI, "techniques")
    vols = []
    for area in os.listdir(tech):
        adir = os.path.join(tech, area)
        if not os.path.isdir(adir):
            continue
        total = 0
        for f in os.listdir(adir):
            if f.endswith(".md") and not f.endswith("-moc.md"):
                total += sum(1 for _ in open(os.path.join(adir, f), encoding="utf-8", errors="ignore"))
        vols.append((area, total))
    return sorted(vols, key=lambda x: x[1])[:n]


def check_emdash():
    """Wiki pages using a PROSE '--' em-dash (vault rule: never use; soft). Ignores code
    (fenced + inline), word--word slugs (TOC anchors / URLs / identifiers), CLI '--flags',
    HTML comments, and table-separator rows, so the count is real violations, not noise."""
    bad = []
    for path in wiki_md(skip_generated=True):
        raw = FENCE_RE.sub("", open(path, encoding="utf-8", errors="ignore").read())
        n = 0
        for ln in raw.splitlines():
            s = INLINE_RE.sub(" ", ln)
            if re.match(r"^[\s|:*_-]+$", s):                 # table separator / hr row
                continue
            for m in re.finditer(r"--+", s):
                before, after = s[m.start()-1:m.start()], s[m.end():m.end()+1]
                if before.isalnum() and after.isalnum():
                    continue                                 # word--word slug/anchor/identifier
                if after[:1].isalnum() and not before.isalnum():
                    continue                                 # --flag option or (#--anchor
                if before == "!" or after == ">":
                    continue                                 # <!-- html comment -->
                n += 1
        if n:
            bad.append((os.path.relpath(path, VAULT), n))
    return bad


def check_placeholder_tools():
    """Wiki pages still carrying the auto-generated '[[tool]]' Tools-section stub (soft)."""
    bad = []
    for path in wiki_md(skip_generated=True):
        if PLACEHOLDER_TOOL in open(path, encoding="utf-8", errors="ignore").read():
            bad.append(os.path.relpath(path, VAULT))
    return bad


def check_image_embeds():
    """Wiki pages embedding an image (vault rule: wiki pages must be image-free; soft)."""
    bad = []
    for path in wiki_md(skip_generated=True):
        text = INLINE_RE.sub("", FENCE_RE.sub("", open(path, encoding="utf-8", errors="ignore").read()))
        n = len(IMG_RE.findall(text))
        if n:
            bad.append((os.path.relpath(path, VAULT), n))
    return bad


def collect():
    have = existing_basenames()
    fm_hard, fm_soft = check_frontmatter()
    return {
        "links": check_broken_links(have),
        "scriptrefs": check_dead_scriptrefs(),
        "playbook": check_playbook(have, VAULT),
        "triggers": check_triggers(VAULT),
        "frontmatter": fm_hard,
        "dateless": fm_soft,
        "stale_index": check_index_stale(),
        "lean": lean_areas(),
        "emdash": check_emdash(),
        "placeholder_tools": check_placeholder_tools(),
        "images": check_image_embeds(),
    }


def main():
    quiet = "-q" in sys.argv or "--summary" in sys.argv
    verbose = "-v" in sys.argv
    r = collect()
    nlinks = len({t for t, _ in r["links"]})
    nrefs = len(r["scriptrefs"])
    npb = len(r["playbook"])
    ntrig = len(r["triggers"])
    nfm = len(r["frontmatter"])
    stale = r["stale_index"]
    hard = nlinks + nrefs + npb + ntrig + nfm + (1 if stale else 0)

    if quiet:
        if hard:
            bits = []
            if nlinks:
                bits.append(f"{nlinks} broken link(s)")
            if nrefs:
                bits.append(f"{nrefs} dead script ref(s)")
            if npb:
                bits.append(f"playbook:{npb}")
            if ntrig:
                bits.append(f"triggers:{ntrig}")
            if nfm:
                bits.append(f"{nfm} frontmatter issue(s)")
            if stale:
                bits.append("index stale")
            print("Wiki lint: " + ", ".join(bits) + " (run scripts/lint-wiki.py).")
        return 1 if hard else 0

    print("=== wiki lint ===")
    print(f"broken wikilinks : {nlinks} distinct missing target(s)")
    if r["links"] and (verbose or nlinks <= 15):
        seen = {}
        for t, f in r["links"]:
            seen.setdefault(t, f)
        for t, f in sorted(seen.items()):
            print(f"    [[{t}]]  <- {f}")
    print(f"dead script refs : {nrefs}")
    for name, f in r["scriptrefs"]:
        print(f"    scripts/{name}  <- {f}")
    print(f"playbook integrity: {npb} issue(s)")
    for loc, why in r["playbook"]:
        print(f"    {why}  <- {loc}")
    print(f"triggers integrity: {ntrig} issue(s)")
    for loc, why in r["triggers"]:
        print(f"    {why}  <- {loc}")
    print(f"frontmatter      : {nfm} hard issue(s); {len(r['dateless'])} page(s) missing a date (soft)")
    if verbose:
        for p, why in r["frontmatter"] + r["dateless"]:
            print(f"    {why}: {p}")
    print(f"index.md         : {'STALE - run scripts/gen_index.py' if stale else 'current'}")
    print("leanest areas    : " + ", ".join(f"{a} ({n}L)" for a, n in r["lean"]))
    em = r["emdash"]
    if em:
        print(f"em-dash (soft)   : {len(em)} page(s), {sum(n for _, n in em)} prose occurrence(s) - vault rule says avoid (comma/semicolon/rewrite)")
        if verbose:
            for p, n in sorted(em, key=lambda x: -x[1])[:20]:
                print(f"    {n}x  {p}")
    ph = r["placeholder_tools"]
    if ph:
        print(f"placeholder tools: {len(ph)} page(s) still carry the [[tool]] stub (soft) - populate or delete the Tools section")
        if verbose:
            for p in sorted(ph)[:20]:
                print(f"    {p}")
    img = r["images"]
    if img:
        print(f"image embeds     : {len(img)} page(s), {sum(n for _, n in img)} embed(s) (soft) - vault rule: wiki pages must be image-free")
        if verbose:
            for p, n in sorted(img, key=lambda x: -x[1]):
                print(f"    {n}x  {p}")
    print(f"\n{'FAIL' if hard else 'OK'}: {hard} hard problem(s)")
    return 1 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
