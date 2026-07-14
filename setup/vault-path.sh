#!/usr/bin/env bash
# Emit the absolute vault root. Portable: explicit env override first, then
# self-locate from this script's real path (it lives in <vault>/setup/), which
# works on any user/path/machine without hardcoding personal paths.
for v in "$OBSIDIAN_VAULT" "$QMD_VAULT" "$CLAUDEBRAIN_VAULT"; do
  [ -n "$v" ] && [ -d "$v" ] && echo "$v" && exit 0
done
SELF="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
if [ -d "$SELF/skills" ] || [ -d "$SELF/wiki" ]; then
  echo "$SELF"
  exit 0
fi
echo "ERROR: vault not found - set OBSIDIAN_VAULT (or QMD_VAULT)" >&2
exit 1
