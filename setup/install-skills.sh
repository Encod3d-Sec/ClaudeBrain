#!/usr/bin/env bash
# Per-device: expose the vault's skills to Claude Code's /skills picker by
# symlinking each SKILL.md-bearing directory into ~/.claude/skills/.
# The hunt skills also auto-fire via the hunt-trigger.py hook (keyword -> invoke);
# this makes them ALSO manually invocable from /skills. Idempotent.
#
#   bash setup/install-skills.sh
#
# Restart Claude Code (or re-open /skills) afterwards so it rescans.
set -euo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
DEST="$HOME/.claude/skills"
mkdir -p "$DEST"

n=0
while IFS= read -r skill; do
  d="$(dirname "$skill")"
  name="$(basename "$d")"
  # Replace any stale real (non-symlink) copy so the vault stays the single
  # source of truth. Such copies drift (old logic survives in ~/.claude); the
  # symlink keeps the runtime skill identical to the vault file.
  if [ -e "$DEST/$name" ] && [ ! -L "$DEST/$name" ]; then
    rm -rf "$DEST/$name"
    echo "replaced stale copy: $name"
  fi
  ln -sfn "$d" "$DEST/$name"
  echo "linked $name"
  n=$((n + 1))
done < <(find "$VAULT/skills" -name SKILL.md)

echo "linked $n vault skills into $DEST"
echo "Restart Claude Code or re-open /skills to see them (hunt-*, research, disclosure, ...)."
