#!/usr/bin/env python3
"""PreToolUse(Bash): BLOCK echo/printf '=== ... ===' banner lines.

They are pure transcript noise (label with no information the command output lacks). Advisory
reminders/memory did not stop them, so this denies the call and forces a rewrite. Fail-open:
any error -> allow.

Scope: ONLY Claude's own decorative banners -- an `echo`/`printf` whose printed string STARTS
with a `===` run (optionally after flags/opening quote). It deliberately does NOT fire when `===`
merely appears later (e.g. `echo "$out"` where output has `===`, `grep "=== Section ==="` on a
tool's output, or a tool/script that integrates `===` in its own output). The `===` must be the
start of what echo/printf prints, which is exactly the hand-written banner form.
"""
import json
import re
import sys

# echo|printf, then optional flags (-e/-n/...), then an optional opening quote, then >=3 '=' :
# matches `echo "=== x ==="`, `echo ===`, `printf '=== %s ==='`, `echo -e "=== x ==="`.
# does NOT match `echo "hello === world"`, `grep "=== x ==="`, `... | grep ===`.
_BANNER = re.compile(r"""\b(?:echo|printf)\b\s+(?:-\w+\s+)*["']?\s*={3,}""")


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if cmd and _BANNER.search(cmd):
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "No '=== ... ===' banner lines (echo/printf) in Bash commands -- pure "
                    "transcript noise. Re-run WITHOUT the banner: let the command output speak, "
                    "and put any labeling in the tool's `description` field, not in echo."),
            }
        }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
