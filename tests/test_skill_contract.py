"""Glob-driven skill-contract lint (spec 1.3, Tier A).

Deterministic, sub-second, zero-API lint over skills/**/SKILL.md. Replaces the
hardcoded 25-name list that used to live in test_wiki_pipeline.py (where a new
hunt skill silently escaped the FIND/OOB contract). Every skill is auto-covered
by globbing, and the per-KIND contract is enforced:

  * every skill:   frontmatter `name` == basename(dir); non-empty bounded `description`.
  * hunt      (skills/hunt/hunt-*):  wiki-first (qmd_query/search) + FIND schema + wiki-stage.py.
  * oob_hunt  (the blind-capable subset ssrf|rce|injection|smuggling|
              deserialization|sqli|cache|xss): additionally an OOB-gate block
              (oob.md row + "Do NOT claim a blind" + "HIT row") and a
              Collaborator/interactsh reference.

Vocab is pinned once in setup/templates/_find.md (canonical-vocab comment) and
asserted here: the FIND filename placeholder is `SEVERITY` (not the drifted
`<SEV>`), and Vuln-index status cells are one of the pinned set.
"""
import glob
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIND_MD = os.path.join(REPO, "setup", "templates", "_find.md")

OOB_CLASSES = {"ssrf", "rce", "injection", "smuggling",
               "deserialization", "sqli", "cache", "xss"}
DESC_MAX = 1024


def _skill_files():
    files = sorted(glob.glob(os.path.join(REPO, "skills", "**", "SKILL.md"), recursive=True))
    assert files, "no SKILL.md files found under skills/**"
    return files


def _read(path):
    return open(path, encoding="utf-8").read()


def _frontmatter(text):
    """Top-level `key: value` pairs from the leading --- ... --- block."""
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    if not m:
        return {}
    fm = {}
    for line in m.group(1).split("\n"):
        km = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if km:
            fm[km.group(1)] = km.group(2).strip()
    return fm


def _kind(path):
    base = os.path.basename(os.path.dirname(path))
    if base.startswith("hunt-"):
        return "oob_hunt" if base[len("hunt-"):] in OOB_CLASSES else "hunt"
    return "skill"


def _pinned_vocab():
    text = _read(FIND_MD)
    ph = re.search(r"^find_filename_placeholder:\s*(\S+)", text, re.M)
    st = re.search(r"^vuln_index_status:\s*(.+)$", text, re.M)
    assert ph and st, "setup/templates/_find.md is missing the canonical-vocab pin"
    placeholder = re.search(r"FIND-XXX-([A-Za-z]+)-", ph.group(1))
    assert placeholder, "find_filename_placeholder pin is malformed: %r" % ph.group(1)
    statuses = {s.strip() for s in st.group(1).split("|") if s.strip()}
    return placeholder.group(1), statuses


# --- per-skill: name + description ------------------------------------------

def test_every_skill_name_matches_dir_and_has_bounded_description():
    bad = []
    for path in _skill_files():
        fm = _frontmatter(_read(path))
        d = os.path.basename(os.path.dirname(path))
        name = fm.get("name", "")
        desc = fm.get("description", "")
        if name != d:
            bad.append("%s: frontmatter name %r != dir %r" % (path, name, d))
        if not (1 <= len(desc) <= DESC_MAX):
            bad.append("%s: description len %d out of bounds (1..%d)" % (path, len(desc), DESC_MAX))
    assert not bad, "skill name/description contract violations:\n" + "\n".join(bad)


# --- hunt kind: wiki-first + FIND + wiki-stage ------------------------------

def test_hunt_skills_carry_wiki_first_find_and_stage():
    bad = []
    for path in _skill_files():
        if _kind(path) not in ("hunt", "oob_hunt"):
            continue
        text = _read(path)
        d = os.path.basename(os.path.dirname(path))
        if not re.search(r"qmd_query|qmd_search", text):
            bad.append("%s: no wiki-first qmd_query/qmd_search" % d)
        if "FIND-" not in text:
            bad.append("%s: no FIND schema reference" % d)
        if "wiki-stage.py" not in text:
            bad.append("%s: no wiki-stage.py distill step" % d)
    assert not bad, "hunt-skill contract violations:\n" + "\n".join(bad)


# --- oob_hunt kind: OOB gate + Collaborator/interactsh ----------------------

def test_oob_capable_hunt_skills_carry_oob_gate():
    bad = []
    seen = set()
    for path in _skill_files():
        if _kind(path) != "oob_hunt":
            continue
        d = os.path.basename(os.path.dirname(path))
        seen.add(d[len("hunt-"):])
        text = _read(path)
        has_block = ("oob.md" in text
                     and "Do NOT claim a blind" in text
                     and "HIT row" in text)
        if not has_block:
            bad.append("%s: missing the OOB-gate block (oob.md row + 'Do NOT claim a blind' + 'HIT row')" % d)
        if not re.search(r"Collaborator|interactsh", text):
            bad.append("%s: missing a Collaborator/interactsh reference" % d)
    missing = OOB_CLASSES - seen
    assert not missing, "expected an oob_hunt skill per class, none found for: %s" % sorted(missing)
    assert not bad, "OOB-gate contract violations:\n" + "\n".join(bad)


# --- pinned vocab: FIND filename placeholder + Vuln-index status -------------

def test_skills_use_pinned_find_vocab():
    placeholder, statuses = _pinned_vocab()
    assert placeholder == "SEVERITY", "pin drifted: FIND placeholder is %r, expected SEVERITY" % placeholder
    assert statuses == {"CONFIRMED", "PARTIAL"}, "pinned status set drifted: %s" % sorted(statuses)

    bad = []
    for path in _skill_files():
        if _kind(path) not in ("hunt", "oob_hunt"):
            continue
        d = os.path.basename(os.path.dirname(path))
        text = _read(path)
        if re.search(r"FIND-(?:XXX|NNN)-<", text):
            bad.append("%s: uses a bracketed severity placeholder; pinned form is FIND-XXX-%s-" % (d, placeholder))
        for line in text.splitlines():
            if "Vuln-index.md:" not in line:
                continue
            sm = re.search(r"\|\s*([A-Z][A-Z ]*[A-Z])\s*\|\s*$", line)
            if sm and sm.group(1) not in statuses:
                bad.append("%s: Vuln-index status %r not in pinned set %s" % (d, sm.group(1), sorted(statuses)))
    assert not bad, "pinned-vocab violations:\n" + "\n".join(bad)
