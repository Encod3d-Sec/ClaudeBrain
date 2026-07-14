#!/usr/bin/env bash
# pocshot.sh - run a command-script in a REAL Kali tmux pane and screenshot the pane (--tmux),
# so the evidence is an ACTUAL tmux session (real commands + real output), not a summary card.
# This is the "same as recon" capture path (recon scans run in tmux, grabbed with --tmux). The
# script should echo `# comments` and `$ commands` then run them, and end with `echo POC-DONE`.
# Pulls the PNG into targets/<eng>/poc/.
#   usage: pocshot <eng> <slug> <local-script.sh>
set -euo pipefail

[ $# -ge 3 ] || { echo "usage: pocshot <eng> <slug> <local-script.sh>" >&2; exit 2; }
ENG="$1"; SLUG="$2"; SCRIPT="$3"
[ -f "$SCRIPT" ] || { echo "pocshot: no such script $SCRIPT" >&2; exit 2; }
VAULT="$(cd "$(dirname "$0")/.." && pwd)"
POC="$VAULT/targets/$ENG/poc"
mkdir -p "$POC"
last=$(ls "$POC" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
NN=$(printf "%02d" $(( 10#${last:-00} + 1 )))
PNG="$NN-$SLUG.png"
SESS="poc_${SLUG//[^a-zA-Z0-9]/_}"

SB64=$(base64 -w0 "$SCRIPT")
SHOTB64=$(base64 -w0 "$VAULT/scripts/shot.py")
# run the script in a fresh wide tmux pane, wait for POC-DONE, screenshot the pane
bash /root/vm.sh "echo '$SHOTB64' | base64 -d > /tmp/shot.py
mkdir -p /tmp/poc; echo '$SB64' | base64 -d > /tmp/$SESS.sh; chmod +x /tmp/$SESS.sh
tmux kill-session -t $SESS 2>/dev/null || true
tmux new-session -d -s $SESS -x 200 -y 200
tmux set-option -t $SESS window-size manual 2>/dev/null || true
tmux resize-window -t $SESS -x 200 -y 200 2>/dev/null || true
tmux send-keys -t $SESS 'clear; bash /tmp/$SESS.sh' C-m
for i in \$(seq 1 60); do tmux capture-pane -p -t $SESS 2>/dev/null | grep -q POC-DONE && break; sleep 1; done
# --history: full scrollback, --maxlines huge: never truncate the PoC
python3 /tmp/shot.py --tmux $SESS --reqresp --history --maxlines 100000 -o /tmp/poc/$PNG >/dev/null 2>&1
tmux kill-session -t $SESS 2>/dev/null || true" >&2

bash /root/vm.sh "base64 -w0 /tmp/poc/$PNG" | base64 -d > "$POC/$PNG"
if [ -s "$POC/$PNG" ]; then
    echo "saved targets/$ENG/poc/$PNG"
    echo "md: ![$SLUG](poc/$PNG)"
else
    echo "pocshot: no PNG produced (tmux/VM issue?)" >&2
    exit 1
fi
