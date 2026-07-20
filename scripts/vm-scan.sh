#!/usr/bin/env bash
# Launch a scan inside a named tmux tab on the Kali VM (root, persistent).
# ONE tmux session per engagement; one window (tab) per PARALLEL scan. By default the window is
# named after the target (sanitize(<target>)), so two scans on the SAME host collide in one tab.
# For parallel scans on one host, give each its OWN window with --win <tool> (e.g. --win nuclei):
# same session, distinct window, NO session-per-scan proliferation. (Never bump the SESSION name
# just to avoid a collision -- that scatters tabs across sessions and breaks one-session recon.)
# Dots/colons/spaces in a name -> '-' (they collide with tmux session:window.pane).
# Windows are targeted by stable window_id so the sanitized name never has to be re-parsed.
# Usage: bash vm-scan.sh [--dry-run] [--win <window-name>] <session> <target> <scan-command...>
set -uo pipefail

DRY=0; WIN=""
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --dry-run) DRY=1; shift;;
    --win) WIN="${2:?--win needs a name}"; shift 2;;
    *) break;;
  esac
done
SESSION="${1:?need <session>}"; TARGET="${2:?need <target>}"; shift 2
SCAN="$*"; : "${SCAN:?need <scan-command...>}"

# sanitize: . : and space -> - . Window name = --win override if given, else the target.
NAME="$(printf '%s' "${WIN:-$TARGET}" | tr './: ' '----')"

# remote tmux script: ensure session, create-or-reuse window, capture id, send scan.
read -r -d '' REMOTE <<EOF || true
tmux has-session -t $SESSION 2>/dev/null || tmux new-session -d -s $SESSION -n main -x 220 -y 50
# force a WIDE detached geometry so tools (nmap -sV, ffuf) don't soft-wrap output at 80 cols,
# which shows up as mid-line breaks in the screenshot card. window-size manual keeps it fixed.
tmux set-option -t $SESSION window-size manual 2>/dev/null
tmux resize-window -t $SESSION -x 220 -y 50 2>/dev/null
WID="\$(tmux list-windows -t '$SESSION' -F '#{window_id} #{window_name}' | awk '\$2=="$NAME"{print \$1; exit}')"
REUSED=1
if [ -z "\$WID" ]; then WID="\$(tmux new-window -t '$SESSION' -P -F '#{window_id}' -n '$NAME')"; REUSED=0; fi
tmux send-keys -t "\$WID" '$SCAN' C-m
echo "window=\$WID name=$NAME session=$SESSION reused=\$REUSED"
EOF

if [ "$DRY" = "1" ]; then
  printf '%s\n' "$REMOTE"
  exit 0
fi

VM_SH="${VM_SH:-/root/vm.sh}"
OUT="$(bash "$VM_SH" "$REMOTE")"
printf '%s\n' "$OUT"
if printf '%s' "$OUT" | grep -q 'reused=1'; then
  # a same-named tab already existed and just got a SECOND command sent into it -- if that tab is
  # still running a DIFFERENT tool, these keystrokes land in its stdin/prompt and corrupt the run
  # (this is exactly how a live feroxbuster scan got clobbered by a nuclei command once). Parallel
  # scans on the same host need a distinct target suffix per tool, e.g. <target>-ferox / <target>-nuclei.
  echo "warn: reused existing tab '$NAME' -- if a DIFFERENT tool is still running there, this command's keystrokes will collide with it. Use a per-tool target suffix for parallel scans on the same host." >&2
fi
# reminder at the point of action: card this tab into recon/ WHEN it finishes (every tool, even empty)
echo "tip: card it when done -> scripts/capture.sh recon $SESSION <slug> $NAME" >&2
