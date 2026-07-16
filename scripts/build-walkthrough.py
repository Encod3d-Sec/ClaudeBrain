#!/usr/bin/env python3
"""build-walkthrough.py - populate an engagement walkthrough.md's Evidence gallery.

The canonical walkthrough structure is `setup/templates/_walkthrough.md` (the
thm_tricipher-structure skeleton: Access/Recon/Foothold/Privesc/Flags/Evidence/
One-shot/Rabbit-holes), which `engagement-init`'s self-heal already writes for a
fresh engagement (substituting <ENGAGEMENT>/<DATE> before it ever reaches disk).
This tool does NOT impose a second, competing structure: it keeps the "## Evidence"
gallery in sync with the PNG evidence cards already rendered to disk
(targets/<eng>/{recon,poc/pages,poc/leads,poc,poc/scripts}/*.png), respecting
whatever structure the walkthrough.md already has.

Core entrypoint (testable, takes an explicit engagement dir so tests do not depend
on the active-engagement pointer):

    build(eng_dir, force=False) -> str
        Existing non-empty walkthrough.md (self-healed template OR an
        operator-filled one) -> refreshes ONLY the "## Evidence" section in place;
        every other byte of the file is preserved. This is the safe, always-correct
        path: the framework template's "## Evidence" heading is followed by
        "## One-shot reproduction (optional)", so the section slice is correct.
        Truly absent/empty/whitespace-only walkthrough.md (or force=True) ->
        scaffolds from the FRAMEWORK template (setup/templates/_walkthrough.md,
        with <ENGAGEMENT>/<DATE> substituted the same way _emit() in
        skills/hooks/_engagement.py does), then runs the same Evidence refresh over
        it. If the template file cannot be read, falls back to the defensive
        built-in _skeleton().

CLI:
    python3 scripts/build-walkthrough.py [<eng>] [--force]
        <eng> is an explicit path, an engagement name under targets/, or omitted
        for the active engagement (targets/active.md).
"""
import glob
import os
import re
import sys
from datetime import date

# self-locate vault, reuse the hooks' active-engagement resolver (same pattern as
# scripts/next_move.py)
VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement  # noqa: E402

# Evidence-scan areas, in the deterministic order the gallery lists them. Each area
# is scanned for *.png (non-recursive), sorted by filename.
AREAS = ("recon", "poc/pages", "poc/leads", "poc", "poc/scripts")

# Section skeleton, in order. "## Evidence" is auto-populated; every other section
# gets a short TODO placeholder.
SECTIONS = (
    "## 0. Access / connectivity",
    "## 1. Recon",
    "## 2. Foothold",
    "## 3. Privilege escalation",
    "## Flags",
    "## Evidence",
    "## One-shot reproduction",
    "## Scripts (full source)",
    "## Rabbit holes (skip on redo)",
)

NO_EVIDENCE = "_No rendered evidence found yet - capture evidence live into poc/ via `capture.sh` (ev/req/tmux/burp)._"

_MANIFEST_ROW = re.compile(r"^\|\s*!\[\]\(([^)]+)\)\s*\|\s*(.*?)\s*\|\s*$")
_LEADING_SEQ = re.compile(r"^\d+-")
_DASH_RUN = re.compile(r"[-_]+")

# known card-type filename shapes, checked (in this order) before the generic
# strip-NNNN-+dash->space fallback
_TMUX_CARD = re.compile(r"^tmux-(.+)$")
_PAGE_CARD = re.compile(r"^\d+-page-")
_SOURCE_CARD = re.compile(r"^\d+-source-")
_LEAD_CARD = re.compile(r"^\d+-lead-")

# _clean_caption helpers
_WHITESPACE_RUN = re.compile(r"\s+")
_LEADING_PROMPT = re.compile(r"^\$\s+")
_SHELL_VAR = re.compile(r"\$\w+|\$\{[^}]+\}")


def _clean_caption(text):
    """Clean a caption sourced from the drain manifest (or, defensively, a
    filename-derived one): collapse internal whitespace, strip a single
    unbalanced trailing quote left by a truncated manifest command, strip a
    leading '$ ' prompt marker, and drop bare unexpanded shell-var tokens
    ($VAR / ${VAR}) without trying to expand them - never raises; an empty
    (or otherwise unusable) result falls back to the original text."""
    if not text:
        return text
    original = text
    try:
        cleaned = _WHITESPACE_RUN.sub(" ", text).strip()
        if cleaned and cleaned[-1] in ("\"", "'") and cleaned.count(cleaned[-1]) % 2 == 1:
            cleaned = cleaned[:-1].rstrip()
        cleaned = _LEADING_PROMPT.sub("", cleaned)
        cleaned = _SHELL_VAR.sub("", cleaned)
        cleaned = _WHITESPACE_RUN.sub(" ", cleaned).strip()
    except Exception:
        return original
    return cleaned or original


def _caption_from_filename(png_basename):
    """Caption derived from a PNG basename when it has no manifest entry.
    Recognizes the known evidence-card shapes and yields a clearer label;
    anything else falls back to stripping a leading NNNN- sequence and the
    extension, turning -/_ into spaces (pure function of the basename)."""
    stem = os.path.splitext(png_basename)[0]

    m = _TMUX_CARD.match(stem)
    if m:
        rest = _DASH_RUN.sub(" ", m.group(1)).strip()
        return "live tmux pane: %s" % rest if rest else "live tmux pane"
    if _PAGE_CARD.match(stem):
        return "browser render + request/response (page capture)"
    if _SOURCE_CARD.match(stem):
        return "leaked source / config capture"
    if _LEAD_CARD.match(stem):
        return "request/response lead card"

    stem = _LEADING_SEQ.sub("", stem)
    stem = _DASH_RUN.sub(" ", stem).strip()
    return stem or png_basename


def _load_manifest(area_dir):
    """Map PNG basename -> caption, parsed from <area_dir>/.pending/manifest.md
    rows shaped '| ![](<area>/<png>) | <caption> |'. Missing/unreadable file, or a
    line that does not match the row shape, is simply skipped (fail gracefully)."""
    captions = {}
    path = os.path.join(area_dir, ".pending", "manifest.md")
    if not os.path.isfile(path):
        return captions
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                m = _MANIFEST_ROW.match(line.strip())
                if not m:
                    continue
                relpath, caption = m.group(1), m.group(2)
                captions[os.path.basename(relpath)] = caption
    except OSError:
        pass
    return captions


def scan_evidence(eng_dir):
    """Scan the fixed evidence areas (in deterministic AREAS order) for *.png, each
    area sorted by filename. Returns a list of (relpath-from-eng_dir, caption).
    A missing area directory is simply an empty scan, not an error."""
    rows = []
    for area in AREAS:
        area_dir = os.path.join(eng_dir, *area.split("/"))
        if not os.path.isdir(area_dir):
            continue
        captions = _load_manifest(area_dir)
        for png in sorted(glob.glob(os.path.join(area_dir, "*.png"))):
            base = os.path.basename(png)
            manifest_caption = captions.get(base)
            caption = _clean_caption(manifest_caption) if manifest_caption else _caption_from_filename(base)
            rows.append((area + "/" + base, caption))
    return rows


def _gallery_lines(eng_dir):
    """The '## Evidence' section body as a list of lines (no trailing blank line):
    heading, blank, then either the table (header + separator + one row per image)
    or the no-evidence placeholder."""
    rows = scan_evidence(eng_dir)
    lines = ["## Evidence", ""]
    if not rows:
        lines.append(NO_EVIDENCE)
    else:
        lines.append("| Evidence | Description |")
        lines.append("| --- | --- |")
        lines.extend("| ![](%s) | %s |" % (relpath, caption) for relpath, caption in rows)
    return lines


def _is_bare(text):
    """True only when walkthrough.md is truly absent/empty/whitespace-only. A
    self-healed-but-unfilled copy of the setup/templates/_walkthrough.md scaffold
    is NOT bare: engagement-init's self-heal already substitutes <ENGAGEMENT>/
    <DATE> before the file ever reaches disk, so those tokens never appear in a
    real engagement's file, and the self-healed template is refreshed in place
    (safe), never rewritten with a competing skeleton."""
    return not text.strip()


def _framework_template_text(eng_dir):
    """Read the canonical setup/templates/_walkthrough.md (the framework's
    thm_tricipher-structure skeleton, maintained by engagement-init) and substitute
    <ENGAGEMENT>/<DATE> exactly the way _emit() in skills/hooks/_engagement.py does
    when it first self-heals the file. Returns None if the template cannot be read
    (defensive: build() falls back to the built-in _skeleton() in that case)."""
    tpl_path = os.path.join(VAULT, "setup", "templates", "_walkthrough.md")
    try:
        with open(tpl_path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return None
    name = os.path.basename(os.path.normpath(eng_dir))
    today = date.today().isoformat()
    return text.replace("<ENGAGEMENT>", name).replace("<DATE>", today)


def _skeleton(eng_dir):
    """Defensive fallback skeleton, used only when the framework template
    (setup/templates/_walkthrough.md) cannot be read: title from the eng dir
    basename, a short TODO placeholder under every non-Evidence section, and the
    auto-populated gallery under '## Evidence'."""
    name = os.path.basename(os.path.normpath(eng_dir))
    lines = ["# Walkthrough - %s" % name, ""]
    for heading in SECTIONS:
        if heading == "## Evidence":
            lines.extend(_gallery_lines(eng_dir))
        else:
            lines.append(heading)
            lines.append("")
            lines.append("_TODO: fill in this section._")
        lines.append("")
    text = "\n".join(lines)
    return text.rstrip("\n") + "\n"


def _insert_gallery(lines, gallery):
    """No '## Evidence' heading exists in the current file: insert the gallery
    immediately before '## One-shot reproduction' when present, else append it at
    the end. Preserves every other line unchanged."""
    for i, line in enumerate(lines):
        if line.startswith("## One-shot reproduction"):
            head = lines[:i]
            if head and head[-1].strip() != "":
                head = head + [""]
            return head + gallery + [""] + lines[i:]
    tail = list(lines)
    while tail and tail[-1] == "":
        tail.pop()
    if tail:
        tail.append("")
    return tail + gallery


def _refresh(existing, eng_dir):
    """Replace ONLY the '## Evidence' section of an existing walkthrough with a
    freshly-scanned gallery: everything from the '## Evidence' heading line up to
    (but not including) the next line starting with '## ' (or EOF) is replaced.
    Every other byte is preserved."""
    lines = existing.split("\n")
    gallery = _gallery_lines(eng_dir)

    ev_idx = None
    for i, line in enumerate(lines):
        if line.strip() == "## Evidence":
            ev_idx = i
            break

    if ev_idx is not None:
        end_idx = len(lines)
        for j in range(ev_idx + 1, len(lines)):
            if lines[j].startswith("## "):
                end_idx = j
                break
        new_lines = lines[:ev_idx] + gallery + [""] + lines[end_idx:]
    else:
        new_lines = _insert_gallery(lines, gallery)

    text = "\n".join(new_lines)
    return text.rstrip("\n") + "\n"


def build(eng_dir, force=False):
    """Scaffold or refresh <eng_dir>/walkthrough.md. Returns the Markdown text
    written (also written to disk). See module docstring for the exact
    absent-vs-existing-narrative behavior."""
    os.makedirs(eng_dir, exist_ok=True)
    wt_path = os.path.join(eng_dir, "walkthrough.md")

    existing = ""
    if os.path.isfile(wt_path):
        with open(wt_path, encoding="utf-8", errors="ignore") as fh:
            existing = fh.read()

    if force or _is_bare(existing):
        base = _framework_template_text(eng_dir)
        text = _refresh(base, eng_dir) if base is not None else _skeleton(eng_dir)
    else:
        text = _refresh(existing, eng_dir)

    with open(wt_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text


def _resolve_eng_dir(arg):
    """Resolve the engagement dir for the CLI: an explicit filesystem path, else
    an engagement NAME under targets/, else the active engagement."""
    if arg:
        if os.path.isdir(arg):
            return os.path.abspath(arg)
        cand = os.path.join(_engagement.TARGETS, arg)
        if os.path.isdir(cand):
            return cand
        return None
    return _engagement.active_dir()


def main():
    force = "--force" in sys.argv[1:]
    positional = [a for a in sys.argv[1:] if a != "--force"]
    arg = positional[0] if positional else None

    eng_dir = _resolve_eng_dir(arg)
    if not eng_dir:
        print("build-walkthrough: no engagement found (pass a path/name, "
              "or set targets/active.md).")
        return 1

    wt_path = os.path.join(eng_dir, "walkthrough.md")
    was_bare = True
    if os.path.isfile(wt_path):
        with open(wt_path, encoding="utf-8", errors="ignore") as fh:
            was_bare = _is_bare(fh.read())

    build(eng_dir, force=force)
    n = len(scan_evidence(eng_dir))
    name = os.path.basename(os.path.normpath(eng_dir))
    action = "wrote fresh skeleton" if (force or was_bare) else "refreshed Evidence gallery"
    print("build-walkthrough: %s for %s (%d evidence image(s))." % (action, name, n))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
