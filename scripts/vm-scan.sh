#!/usr/bin/env bash
# Launch a scan inside a named tmux tab on the Kali VM (root, persistent).
# One tmux session per engagement; one window (tab) per target, named to correlate:
#   sanitize(<target>)   (a multi-web target passes <target>-web-<IP-or-Domain>)
# Dots/colons/spaces in the name -> '-' (they collide with tmux session:window.pane).
# Windows are targeted by stable window_id so the sanitized name never has to be re-parsed.
# Usage: bash vm-scan.sh [--dry-run] <session> <target> <scan-command...>
set -uo pipefail

DRY=0
if [ "${1:-}" = "--dry-run" ]; then DRY=1; shift; fi
SESSION="${1:?need <session>}"; TARGET="${2:?need <target>}"; shift 2
SCAN="$*"; : "${SCAN:?need <scan-command...>}"

# sanitize: . : and space -> -
NAME="$(printf '%s' "$TARGET" | tr './: ' '----')"

# remote tmux script: ensure session, create-or-reuse window, capture id, send scan.
read -r -d '' REMOTE <<EOF || true
tmux has-session -t $SESSION 2>/dev/null || tmux new-session -d -s $SESSION -n main -x 220 -y 50
# force a WIDE detached geometry so tools (nmap -sV, ffuf) don't soft-wrap output at 80 cols,
# which shows up as mid-line breaks in the screenshot card. window-size manual keeps it fixed.
tmux set-option -t $SESSION window-size manual 2>/dev/null
tmux resize-window -t $SESSION -x 220 -y 50 2>/dev/null
WID="\$(tmux list-windows -t '$SESSION' -F '#{window_id} #{window_name}' | awk '\$2=="$NAME"{print \$1; exit}')"
if [ -z "\$WID" ]; then WID="\$(tmux new-window -t '$SESSION' -P -F '#{window_id}' -n '$NAME')"; fi
tmux send-keys -t "\$WID" '$SCAN' C-m
echo "window=\$WID name=$NAME session=$SESSION"
EOF

if [ "$DRY" = "1" ]; then
  printf '%s\n' "$REMOTE"
  exit 0
fi

VM_SH="${VM_SH:-/root/vm.sh}"
bash "$VM_SH" "$REMOTE"

# Area 2 (always-capture-evidence): record the launched tab so loop-driver's
# drain_pending_tmux() can auto-grab the live pane into recon/ without an operator
# following the tmux_capture_guidance() nudge by hand. Resolved via targets/active.md,
# the same pointer the rest of the harness uses. CLAUDEBRAIN_VAULT overrides the vault
# root (same env var the python hooks honor) so tests can point at a fixture vault
# instead of the real, private targets/ tree. Fail-open: no active engagement -> just
# skip (the manual nudge still fires from recon-capture.py).
VAULT="${CLAUDEBRAIN_VAULT:-$(cd "$(dirname "$0")/.." && pwd)}"
ACTIVE="$VAULT/targets/active.md"
if [ -f "$ACTIVE" ]; then
  ENG="$(grep -vE '^[[:space:]]*(#|<!--|-|\*)' "$ACTIVE" 2>/dev/null \
         | grep -vE '^[[:space:]]*$' | head -1 | tr -d '[:space:]')"
  if [ -n "$ENG" ] && [ -d "$VAULT/targets/$ENG" ]; then
    printf '%s:%s\n' "$SESSION" "$NAME" >> "$VAULT/targets/$ENG/.pending-tmux"
  fi
fi
