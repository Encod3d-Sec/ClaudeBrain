#!/usr/bin/env python3
"""wiki-promote.py - review and promote staged wiki candidates into wiki/.

The ONLY path that writes engagement-derived knowledge into wiki/, and it always
runs the leak-check first, so the client-data boundary is enforced by code.

    python3 scripts/wiki-promote.py --list
    python3 scripts/wiki-promote.py --review <slug>
    python3 scripts/wiki-promote.py --promote <slug|all>
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "skills", "hooks"))
import _engagement  # noqa: E402

FM_RE = re.compile(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)$", re.S)
KINDS = ("default-cred", "api-pattern", "technique")


def inbox_dir():
    d = _engagement.active_dir()
    return os.path.join(d, "wiki-candidates") if d else None


def split_fm(text):
    """(fm_dict, body). Empty dict + original text if there is no frontmatter.

    Frontmatter keys are parsed via _engagement._frontmatter - the same canonical,
    tolerant parser engagement-init's wiki_candidate_count uses - so all pending-
    detection call sites (wiki-stage, wiki-promote, engagement-init) agree on what
    counts as pending. Only the body-splitting stays local to this function."""
    m = FM_RE.match(text)
    if not m:
        return {}, text
    return _engagement._frontmatter(text), m.group(2)


def candidates(inbox, pending_only=True):
    """[(path, fm, body)] for *.md in inbox (skips _promoted/ and _-prefixed files)."""
    out = []
    if not inbox or not os.path.isdir(inbox):
        return out
    for f in sorted(os.listdir(inbox)):
        if not f.endswith(".md") or f.startswith("_"):
            continue
        p = os.path.join(inbox, f)
        if not os.path.isfile(p):
            continue
        fm, body = split_fm(open(p, encoding="utf-8", errors="ignore").read())
        if pending_only and fm.get("status", "").lower() != "pending":
            continue
        out.append((p, fm, body))
    return out


def _first_body_line(body):
    for line in body.splitlines():
        if line.strip():
            return line.strip()
    return ""


def cmd_list(inbox):
    rows = candidates(inbox)
    if not rows:
        print("no pending wiki candidates.")
        return 0
    for p, fm, body in rows:
        print("%s  [%s]  -> wiki/%s\n    %s"
              % (fm.get("slug", os.path.basename(p)[:-3]), fm.get("kind", "?"),
                 fm.get("target_page", "?"), _first_body_line(body)[:100]))
    return 0


def cmd_review(inbox, slug):
    for p, fm, body in candidates(inbox, pending_only=False):
        if fm.get("slug") == slug or os.path.basename(p)[:-3] == slug:
            print(open(p, encoding="utf-8", errors="ignore").read())
            return 0
    print("no such candidate: %s" % slug, file=sys.stderr)
    return 1


def leak_check(body, vault, source_eng=""):
    """(ok, report). Writes the BODY only to a temp file and runs
    scripts/check-leaks.sh --file on it (mechanical client-marker gate).
    When source_eng is given, also passes --eng so the gate additionally derives
    scope-host markers from THAT engagement - the candidate's actual source -
    instead of only whichever engagement happens to be active.
    Fails CLOSED: a missing gate script must refuse, never read as clean."""
    script = os.path.join(vault, "scripts", "check-leaks.sh")
    if not os.path.isfile(script):
        return False, "check-leaks.sh not found; failing closed"
    fd, tmp = tempfile.mkstemp(suffix=".md")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        cmd = ["bash", script, "--file", tmp]
        if source_eng:
            cmd += ["--eng", source_eng]
        r = subprocess.run(cmd, cwd=vault,
                           capture_output=True, text=True, timeout=60)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def resolve_target(vault, target_rel):
    """(target_path, ok). Resolves target_rel under wiki/ and refuses any escape
    (../ segments or an absolute path) BEFORE the caller does any read/write of it."""
    wiki_root = os.path.realpath(os.path.join(vault, "wiki"))
    target_path = os.path.realpath(os.path.join(vault, "wiki", target_rel))
    ok = target_path == wiki_root or target_path.startswith(wiki_root + os.sep)
    return target_path, ok


def already_promoted(target_path, slug):
    try:
        return ("promoted-slug: " + slug) in open(
            target_path, encoding="utf-8", errors="ignore").read()
    except OSError:
        return False


def _row_of(body):
    for line in body.splitlines():
        if line.strip().startswith("|"):
            return line.strip()
    return ""


def merge_row(target_path, row_line, slug):
    """Insert a table row into the target page's first markdown table; append the
    dedup marker at EOF. No-op if the slug is already promoted."""
    if already_promoted(target_path, slug):
        return
    lines = open(target_path, encoding="utf-8", errors="ignore").read().splitlines()
    end, in_tbl = None, False
    for i, l in enumerate(lines):
        if l.lstrip().startswith("|"):
            in_tbl, end = True, i
        elif in_tbl:
            break
    if end is None:
        lines.append(row_line)
    else:
        lines.insert(end + 1, row_line)
    out = "\n".join(lines).rstrip() + "\n\n<!-- promoted-slug: %s -->\n" % slug
    open(target_path, "w", encoding="utf-8").write(out)


def merge_section(target_path, body, slug):
    """Append a technique section (body carries its own ## heading) + dedup marker."""
    if already_promoted(target_path, slug):
        return
    text = open(target_path, encoding="utf-8", errors="ignore").read().rstrip() + "\n\n"
    text += body.rstrip() + "\n\n<!-- promoted-slug: %s -->\n" % slug
    open(target_path, "w", encoding="utf-8").write(text)


def set_promoted_and_archive(path, inbox, slug):
    text = open(path, encoding="utf-8", errors="ignore").read()
    text = re.sub(r"(?m)^status:\s*pending\s*$", "status: promoted", text)
    open(path, "w", encoding="utf-8").write(text)
    arch = os.path.join(inbox, "_promoted")
    os.makedirs(arch, exist_ok=True)
    shutil.move(path, os.path.join(arch, slug + ".md"))


def reindex(vault):
    """Re-catalog (gen_index.py) + refresh the search index (qmd update, best-effort)."""
    gi = os.path.join(vault, "scripts", "gen_index.py")
    if os.path.isfile(gi):
        try:
            subprocess.run(["python3", gi], cwd=vault, capture_output=True, text=True, timeout=40)
        except Exception:
            pass
    try:
        subprocess.run(["qmd", "update"], cwd=vault, capture_output=True, text=True, timeout=90)
    except Exception:
        pass


def promote_one(path, fm, body, inbox, vault):
    """Returns 'promoted' | 'refused' | 'skipped'."""
    slug = fm.get("slug") or os.path.basename(path)[:-3]
    kind = fm.get("kind", "")
    target_rel = fm.get("target_page", "")
    if not target_rel:
        print("  %s: target page wiki/%s not found -> skipped" % (slug, target_rel))
        return "skipped"
    target_path, in_wiki = resolve_target(vault, target_rel)
    if not in_wiki:
        print("  %s: target_page '%s' escapes wiki/ -> REFUSED" % (slug, target_rel))
        return "refused"
    if not os.path.isfile(target_path):
        print("  %s: target page wiki/%s not found -> skipped" % (slug, target_rel))
        return "skipped"
    if os.path.exists(os.path.join(inbox, "_promoted", slug + ".md")) \
            or already_promoted(target_path, slug):
        print("  %s: already promoted -> skipped" % slug)
        return "skipped"
    if kind not in KINDS:
        print("  %s: unknown kind '%s' -> REFUSED" % (slug, kind))
        return "refused"
    ok, report = leak_check(body, vault, fm.get("source_eng", ""))
    if not ok:
        print("  %s: LEAK-GATE REFUSED (not written to wiki):" % slug)
        for line in report.splitlines():
            print("    " + line)
        return "refused"
    if kind in ("default-cred", "api-pattern"):
        row = _row_of(body)
        if not row:
            print("  %s: no table row in body -> skipped" % slug)
            return "skipped"
        merge_row(target_path, row, slug)
    else:                                    # technique
        merge_section(target_path, body, slug)
    set_promoted_and_archive(path, inbox, slug)
    print("  %s: promoted -> wiki/%s" % (slug, target_rel))
    return "promoted"


def cmd_promote(inbox, which, vault):
    rows = candidates(inbox)
    if which != "all":
        rows = [r for r in rows
                if r[1].get("slug") == which or os.path.basename(r[0])[:-3] == which]
        if not rows:
            print("no such pending candidate: %s" % which, file=sys.stderr)
            return 1
    n_prom = n_ref = 0
    for path, fm, body in rows:
        res = promote_one(path, fm, body, inbox, vault)
        n_prom += res == "promoted"
        n_ref += res == "refused"
    if n_prom:
        reindex(vault)
    print("promoted %d, refused %d" % (n_prom, n_ref))
    return 1 if n_ref else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Review/promote staged wiki candidates.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--review", metavar="SLUG")
    g.add_argument("--promote", metavar="SLUG|all")
    args = ap.parse_args(argv)

    inbox = inbox_dir()
    if not inbox:
        print("no active engagement (set targets/active.md)", file=sys.stderr)
        return 1
    if args.list:
        return cmd_list(inbox)
    if args.review:
        return cmd_review(inbox, args.review)
    return cmd_promote(inbox, args.promote, _engagement.VAULT)


if __name__ == "__main__":
    sys.exit(main())
