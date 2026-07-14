#!/usr/bin/env bash
# Scaffold a CVE-research project workspace under raw/research/.
#
#   bash setup/new-research.sh <project_name>
#
# Creates raw/research/<project_name>/{target,surface,findings,deadends,loop}.md + poc/.
# raw/ is otherwise read-only; research/<project>/ is the sanctioned writable
# research workspace (public-target research, not client data).
set -euo pipefail

NAME="${1:-}"
[ -n "$NAME" ] || { echo "usage: new-research.sh <project_name>"; exit 1; }
# normalise to a safe slug
NAME="$(printf '%s' "$NAME" | tr ' /' '--' | tr -cd 'A-Za-z0-9._-')"
[ -n "$NAME" ] || { echo "invalid project name"; exit 1; }

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
TPL="$VAULT/setup/templates/research"
DEST="$VAULT/raw/research/$NAME"
TODAY="$(date +%F)"

[ -d "$TPL" ] || { echo "template missing: $TPL"; exit 1; }
[ -e "$DEST" ] && { echo "already exists: $DEST"; exit 1; }

mkdir -p "$DEST/poc"
for f in target surface findings deadends loop; do
  sed -e "s/<PROJECT>/$NAME/g" -e "s/<DATE>/$TODAY/g" "$TPL/$f.md" > "$DEST/$f.md"
done

printf '%s\n' "$NAME" > "$VAULT/raw/research/active.md"   # set as the active research project

echo "created research project: raw/research/$NAME/ (target, surface, findings, deadends, loop, poc/)"
echo "active research project set to: $NAME (raw/research/active.md)"
echo "1. fill target.md (what / version / build / run)"
echo "2. invoke the research skill to start the loop (SessionStart will surface its status + next moves)"
