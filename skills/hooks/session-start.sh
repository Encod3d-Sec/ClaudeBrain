#!/usr/bin/env bash
# Self-locate the vault root from this script's real path (resolves the
# ~/.claude/vault-hooks symlink -> skills/hooks/, so ../.. is the vault root).
# Honor explicit overrides first so it works on any user/path/spelling.
VAULT="${QMD_VAULT:-${CLAUDEBRAIN_VAULT:-$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)}}"

# Auto-register vault skills so a freshly-authored skill is invocable without a
# manual `setup/install-skills.sh` run. Idempotent (symlinks each skills/*/SKILL.md
# into ~/.claude/skills/, skipping existing); the harness rescans on session start.
# Output suppressed so it never pollutes the context injected below; fails open.
bash "$VAULT/setup/install-skills.sh" >/dev/null 2>&1 || true

# Inject session hot cache into context
HOT="$VAULT/session/hot.md"
[ -f "$HOT" ] && cat "$HOT"
exit 0   # fail open: never let a missing hot.md make the SessionStart hook exit non-zero
