---
name: nday
description: N-day / patch-diff workflow - given a CVE/advisory or a suspicious patch, diff pre- vs post-patch to locate the fixed bug, build a PoC for the unpatched version, and run variant analysis for a fresh bug. Triggers - "n-day", "patch diff", "diff the patch", "bindiff".
---

# N-day / Patch Diffing

Turn a patched vulnerability into a working PoC, or surface a silently-patched bug. Read [[nday-patch-diffing]] first.

## Procedure
1. **Acquire both versions** - vulnerable + fixed: git tags, release assets, distro packages, or vendor binaries.
2. **Diff:**
   - source: `git log <fixtag>~5..<fixtag>` then `git diff <vulntag> <fixtag>` over the suspect path; read the changed function.
   - binary: BinDiff / Diaphora / [[ghidra]] Version Tracking; open functions flagged changed (not just recompiled).
3. **Root-cause from the diff** - what the patch *adds* (bounds/auth/sanitization check) reveals what was missing; trace the now-checked value back to attacker input.
4. **Build the trigger** - craft input that reaches the pre-patch unchecked path; reproduce on the vulnerable build; confirm **reachability** in a realistic config.
5. **Variant analysis** - grep / [[codeql]] for the same flawed pattern the patch did not touch -> potential **new** CVE (then hand off to the `disclosure` skill).

## Output
- PoC/trigger in `raw/research/<project>/poc/` and the bug recorded in `findings.md` (mark `n-day CVE-xxxx` or `candidate` if a new variant).
- Note affected/fixed versions and the exact patch commit.

## Wiki feedback
Reusable diffing trick or a found variant pattern -> update [[nday-patch-diffing]] (or the matching technique page via `research-ingest`).

Report: target patch, located bug, PoC status, any variant found.
