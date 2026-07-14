#!/usr/bin/env python3
"""PreToolUse(Write|Edit) hook: keep client data OUT of the generic session/ files.

session/hot.md, log.md, memory.md are framework/methodology only and auto-load at
SessionStart. This advisory warns (never blocks) when a write to one of them carries
an active-engagement marker (the engagement dir name or a scope host/domain), so the
narrative is routed to targets/<eng>/log.md (gitignored) instead. Fails open.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SESSION_FILES = {"hot.md", "log.md", "memory.md"}


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
    base = os.path.basename(fp)
    if base not in SESSION_FILES or "/session/" not in fp:
        return
    if "/targets/" in fp:
        return  # per-engagement files are the CORRECT destination
    content = " ".join(str(ti.get(k, "")) for k in ("content", "new_string", "old_string")).lower()
    if not content:
        return
    hits = sorted(m for m in markers() if m in content)
    if not hits:
        return
    msg = ("CLIENT-DATA BOUNDARY - this write puts engagement marker(s) "
           + ", ".join(hits[:5]) + f" into session/{base}, which is generic and auto-loaded "
           "at every SessionStart. Put per-engagement narrative in targets/<eng>/log.md "
           "(the audit trail) instead - it is gitignored. Keep session/ "
           "framework/methodology only.")
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
