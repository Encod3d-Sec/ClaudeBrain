#!/usr/bin/env bash
# reqshot.sh - capture the REAL curl request+response as a terminal card, presentable as
# full-file PoC to a client / CTF writeup. Runs `curl -sS -iv <args>` on the Kali VM (request
# line+headers via `>`, response status+headers+body via `<`), prepends the exact curl command
# (so the request BODY is visible too), renders a colored request/response terminal card, and
# pulls the PNG into targets/<eng>/poc/. Use this for any target request whose result is a lead.
#
#   usage: reqshot <eng> <slug> [--] <curl-args...>
#   e.g.:  reqshot thm_tricipher flag1-login -- -X POST https://10.112.144.18:5000/login \
#             -d 'mac=..&data=..&sign=..' -k
#
# For crypto-forged requests, have the exploit script print the concrete curl (its `--curl`
# mode), then paste those args here so the PoC is a reproducible curl, not "run my python".
set -euo pipefail

[ $# -ge 3 ] || { echo "usage: reqshot <eng> <slug> [--] <curl-args...>" >&2; exit 2; }
ENG="$1"; SLUG="$2"; shift 2
[ "${1:-}" = "--" ] && shift
[ $# -ge 1 ] || { echo "reqshot: no curl args given" >&2; exit 2; }

VAULT="$(cd "$(dirname "$0")/.." && pwd)"
POC="$VAULT/targets/$ENG/poc"
mkdir -p "$POC"
last=$(ls "$POC" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
NN=$(printf "%02d" $(( 10#${last:-00} + 1 )))
PNG="$NN-$SLUG.png"
LOG="/tmp/poc/$SLUG.reqresp"

# Build a bash-safe curl invocation (%q quotes each arg for the remote bash), then base64 the
# whole remote script so the SSH transport never sees the +/=/&/quote chars in a forged body.
CURL="curl -sS -iv"
for a in "$@"; do CURL+=" $(printf '%q' "$a")"; done
REMOTE=$(cat <<EOF
mkdir -p /tmp/poc
{ echo "\$ $CURL"; echo; $CURL ; } > "$LOG" 2>&1 || true
EOF
)
RB64=$(printf '%s' "$REMOTE" | base64 -w0)
SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")

# render on the VM: run the request, card it (request/response coloring, full length)
bash /root/vm.sh "echo '$SHOT_B64' | base64 -d > /tmp/shot.py
echo '$RB64' | base64 -d > /tmp/reqshot_cmd.sh
bash /tmp/reqshot_cmd.sh
python3 /tmp/shot.py --term '$LOG' --reqresp --cmd 'curl -iv  (request + response)' --maxlines 600 -o /tmp/poc/$PNG" >&2

# pull the PNG into the vault (base64 through the pipe, not the caller's context)
bash /root/vm.sh "base64 -w0 /tmp/poc/$PNG" | base64 -d > "$POC/$PNG"

if [ -s "$POC/$PNG" ]; then
    echo "saved targets/$ENG/poc/$PNG"
    echo "md: ![curl request+response - $SLUG](poc/$PNG)"
else
    echo "reqshot: no PNG produced (VM unreachable? curl args wrong?)" >&2
    exit 1
fi
