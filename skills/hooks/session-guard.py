#!/usr/bin/env python3
"""PreToolUse(Write|Edit) hook: keep client data OUT of generic/shareable files.

Two destinations are guarded, both advisory (never block), both fail open:
  - session/{hot,log,memory}.md - framework/methodology only, auto-loaded at SessionStart.
  - git-TRACKED framework trees (wiki/ scripts/ skills/ docs/ tests/ setup/) - shared on commit.
When a write to either carries an active-engagement marker (the engagement dir name, >=4 chars,
or a scope host/domain), warn: the narrative/codename belongs ONLY in targets/<eng>/ (gitignored),
or - for the retrospective - in the gitignored docs/superpowers/ tree. This catches the recurring
"active codename baked into a tracked comment/log" leak at WRITE time, before check-leaks fails at
commit time. Fails open.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SESSION_FILES = {"hot.md", "log.md", "memory.md"}
# tracked, shareable framework trees: an engagement codename/host must never land here. Only
# targets/<eng>/ (gitignored) or docs/superpowers/ (gitignored planning+retro) may name an engagement.
TRACKED_TREES = ("/wiki/", "/scripts/", "/skills/", "/docs/", "/tests/", "/setup/")


def _dest_kind(fp):
    """'session' | 'tracked' | None (not a guarded destination)."""
    if "/targets/" in fp:
        return None                         # the CORRECT, gitignored destination
    if "/docs/superpowers/" in fp:
        return None                         # gitignored planning/retro may name the engagement
    if os.path.basename(fp) in SESSION_FILES and "/session/" in fp:
        return "session"
    if any(t in fp for t in TRACKED_TREES):
        return "tracked"
    return None


def markers():
    """Active-engagement client markers: dir name segment(s) + scope hosts/domains."""
    out = set()
    try:
        import _engagement
        d = _engagement.active_dir()
        if d:
            rel = os.path.relpath(d, _engagement.TARGETS).replace("\\", "/")
            for seg in rel.split("/"):
                seg = seg.strip().lower()
                if len(seg) >= 4 and seg not in (".", ".."):
                    out.add(seg)
            sc = _engagement.scope(d) or {}
            for k in ("in_scope", "out_of_scope"):
                for v in sc.get(k, []):
                    v = (v or "").strip().lower()
                    if v and "/" not in v and " " not in v and len(v) >= 4:
                        out.add(v)
    except Exception:
        pass
    return out


def main():
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return
    ti = data.get("tool_input") or {}
    fp = (ti.get("file_path", "") or "").replace("\\", "/")
    kind = _dest_kind(fp)
    if not kind:
        return
    content = " ".join(str(ti.get(k, "")) for k in ("content", "new_string", "old_string")).lower()
    if not content:
        return
    hits = sorted(m for m in markers() if m in content)
    if not hits:
        return
    joined = ", ".join(hits[:5])
    if kind == "session":
        msg = ("CLIENT-DATA BOUNDARY - this write puts engagement marker(s) " + joined
               + f" into session/{os.path.basename(fp)}, which is generic and auto-loaded "
               "at every SessionStart. Put per-engagement narrative in targets/<eng>/log.md "
               "(the audit trail) instead - it is gitignored. Keep session/ "
               "framework/methodology only.")
    else:  # tracked
        msg = ("CLIENT-DATA BOUNDARY - this write puts engagement marker(s) " + joined
               + " into a git-TRACKED framework file (shared on commit). Client/engagement "
               "specifics live ONLY under targets/<eng>/ (gitignored); a reusable lesson goes "
               "in generically, with NO codename. Genericize before writing (the retro under "
               "docs/superpowers/ may name it), or run scripts/check-leaks.sh before commit.")
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": msg,
        }
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
