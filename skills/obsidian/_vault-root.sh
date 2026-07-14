#!/usr/bin/env bash
# Thin wrapper - delegates to setup/vault-path.sh regardless of CWD.
# Skills call: VAULT=$(bash ~/.claude/skills/obsidian/_vault-root.sh)
# Self-locate the vault root from this script's real path (resolves the
# ~/.claude/skills symlink: skills/obsidian/ -> ../.. is the vault root).
ROOT="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
exec bash "$ROOT/setup/vault-path.sh"
