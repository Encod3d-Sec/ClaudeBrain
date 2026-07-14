#!/usr/bin/env bash
# evshot.sh - ONE-CALL live evidence capture. Call it the MOMENT a step LANDS (a cred, a
# decoded response, a flag), NOT at the end of the box. A card taken live is situational
# awareness you (and the operator watching) can act on to find the next move; a card taken
# after the box is over is only a trophy. It renders a terminal card that shows BOTH the
# command that was run AND the request URL it hit, then pulls the PNG into the engagement
# poc/ and prints the walkthrough ref. cmd + url are REQUIRED args so no card is anonymous.
#
# Workflow (two trivial lines, safe for stateful exploits - no re-execution):
#   1) tee the output of the step you just ran, on the VM:
#        bash /root/vm.sh 'python3 /tmp/exploit.py 2>&1 | tee /tmp/poc/flag3.log'
#   2) card + pull it into the vault, live:
#        scripts/evshot.sh thm_tricipher flag3-contract \
#            "POST http://10.112.144.18:8545 (eth_sendTransaction) -> GET /challenge/solve" \
#            "reset()+transferDeposit() then /challenge/solve"
#
#   args:  <eng> <slug> <request-url> <cmd-label> [logfile=/tmp/poc/<slug>.log]
#   Auto-numbers NN from the existing poc/NN-*.png so cards stay in engagement order.
set -euo pipefail

[ $# -ge 4 ] || { echo "usage: evshot.sh <eng> <slug> <request-url> <cmd-label> [logfile]" >&2; exit 2; }
ENG="$1"; SLUG="$2"; URL="$3"; CMD="$4"; LOG="${5:-/tmp/poc/$SLUG.log}"
VAULT="$(cd "$(dirname "$0")/.." && pwd)"
POC="$VAULT/targets/$ENG/poc"
mkdir -p "$POC"

# next NN index (10# forces base-10 so 08->09, not octal); empty poc/ -> 01
last=$(ls "$POC" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
NN=$(printf "%02d" $(( 10#${last:-00} + 1 )))
PNG="$NN-$SLUG.png"

# ensure shot.py is on the VM, render the card (cmd in title bar + url in address bar)
B64=$(base64 -w0 "$VAULT/scripts/shot.py")
bash /root/vm.sh "mkdir -p /tmp/poc; echo '$B64' | base64 -d > /tmp/shot.py
python3 /tmp/shot.py --term '$LOG' --cmd \"$CMD\" --url-bar \"$URL\" -o /tmp/poc/$PNG" >&2

# pull the PNG into the vault poc/ (base64 flows through the pipe, not the caller's context)
bash /root/vm.sh "base64 -w0 /tmp/poc/$PNG" | base64 -d > "$POC/$PNG"

if [ -s "$POC/$PNG" ]; then
    echo "saved targets/$ENG/poc/$PNG"
    echo "md: ![$CMD](poc/$PNG)"
else
    echo "evshot: no PNG produced - did you tee the step output to $LOG on the VM first?" >&2
    exit 1
fi
