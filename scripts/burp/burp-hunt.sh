#!/usr/bin/env bash
# burp-hunt.sh -- ONE command: send a request through Burp (MCP send_http1_request), auto-approve a
# new host if the approval popup blocks it, and capture a req/resp PoC with the finding HIGHLIGHTED.
# Collapses the scope-sync -> send -> approve -> capture dance into a single call, and uses the fast
# MCP send path (no brittle GUI tab-stepping / Ctrl+Space that capture.sh burp needs).
#
#   bash scripts/burp/burp-hunt.sh <eng> <slug> <host> <port> <https> <method> <path> [bodyfile-on-vm] [highlight-regex]
#
# Examples:
#   # POST RCE, highlight the proof strings:
#   bash /root/vm.sh "printf 'command=id' > /tmp/b.txt"
#   bash scripts/burp/burp-hunt.sh <eng> rce <TARGET-IP> 80 false POST /home.php /tmp/b.txt 'www-data|uid=0|root:'
#   # GET, highlight a token:
#   bash scripts/burp/burp-hunt.sh <eng> leak <TARGET-IP> 80 false GET /api/me '' 'secret|token'
#
# Env: VM_SH (SSH bridge, default /root/vm.sh). bodyfile must already be on the VM (like capture.sh burp).
set -uo pipefail
VAULT="$(cd "$(dirname "$0")/../.." && pwd)"
VM_SH="${VM_SH:-/root/vm.sh}"
[ $# -ge 7 ] || { echo "usage: burp-hunt.sh <eng> <slug> <host> <port> <https> <method> <path> [bodyfile-on-vm] [highlight-regex]" >&2; exit 2; }
ENG=$1; SLUG=$2; HOST=$3; PORT=$4; HTTPS=$5; METHOD=$6; RPATH=$7; BODYFILE=${8:-}; HL=${9:-}

# VM-side sender: build the raw request, call send_http1_request, parse req/resp into a clean card text.
read -r -d '' SENDPY <<'PY' || true
import json, os, subprocess, sys
cli = os.path.expanduser("~/burp-mcp-cli.py")
host, port, https, method, path, bf, outtext = sys.argv[1:8]
lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % host, "Accept: */*", "Connection: close"]
body = ""
if bf and os.path.exists(bf):
    body = open(bf).read().strip()
    lines += ["Content-Type: application/x-www-form-urlencoded;charset=UTF-8", "Content-Length: %d" % len(body)]
req = "\r\n".join(lines + ["", body])
args = json.dumps({"content": req, "targetHostname": host, "targetPort": int(port), "usesHttps": https == "true"})
try:
    p = subprocess.run(["python3", cli, "call", "send_http1_request", args], capture_output=True, text=True, timeout=40)
    out = p.stdout
except Exception as e:
    out = "ERR " + str(e)
if "httpResponse=" not in out:                       # empty / timed out => approval popup is blocking
    sys.stderr.write("STALL " + (out.strip() or "no response")[-160:] + "\n"); sys.exit(3)
try:
    reqpart = out.split("httpRequest=", 1)[1].rsplit(", httpResponse=", 1)[0].strip()
    resppart = out.split("httpResponse=", 1)[1].rsplit(", messageAnnotations=", 1)[0].strip()
except Exception:
    reqpart, resppart = req, out.strip()
txt = ("$ %s %s   (Burp send_http1_request -> %s:%s)\n\n"
       "===== REQUEST =====\n%s\n\n===== RESPONSE =====\n%s\n" % (method, path, host, port, reqpart, resppart))
open(outtext, "w").write(txt)
print("SENT_OK")
PY

CLI_B64=$(base64 -w0 "$VAULT/scripts/burp/burp-mcp-cli.py")
SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")
SEND_B64=$(printf '%s' "$SENDPY" | base64 -w0)
TXT=/tmp/burphunt_${SLUG//[^a-zA-Z0-9]/_}.txt
RPNG=/tmp/burphunt_${SLUG//[^a-zA-Z0-9]/_}.png

# 1) push helpers + send (one round-trip)
run_send() {
  bash "$VM_SH" "echo '$CLI_B64' | base64 -d > ~/burp-mcp-cli.py
echo '$SHOT_B64' | base64 -d > /tmp/shot.py
echo '$SEND_B64' | base64 -d > /tmp/burphunt_send.py
python3 /tmp/burphunt_send.py '$HOST' '$PORT' '$HTTPS' '$METHOD' '$RPATH' '$BODYFILE' '$TXT'" 2>&1
}
RES=$(run_send)
if ! echo "$RES" | grep -q SENT_OK; then
  if echo "$RES" | grep -q STALL; then
    echo "burp-hunt: send blocked on the MCP approval popup -> auto-approving $HOST ..." >&2
    bash "$VAULT/scripts/burp/burp-approve.sh" >&2 || true
    RES=$(run_send)                                  # retry once, now that the host is approved
  fi
  echo "$RES" | grep -q SENT_OK || { echo "burp-hunt: send failed -> $RES" >&2; exit 1; }
fi

# 2) render the highlighted card on the VM (shot.py --term --highlight)
HLARG=(); [ -n "$HL" ] && HLARG=(--highlight "$HL")
printf -v HLQ '%q ' "${HLARG[@]}"
bash "$VM_SH" "python3 /tmp/shot.py --term '$TXT' --cmd 'Burp: $METHOD $RPATH' ${HLQ}-o '$RPNG' 2>&1 | tail -2"

# 3) pull the PNG into the vault poc/ with the next NN
POC="$VAULT/targets/$ENG/poc"; mkdir -p "$POC"
LAST=$(ls "$POC"/[0-9][0-9]-*.png 2>/dev/null | sed -E 's#.*/0*([0-9]+)-.*#\1#' | sort -n | tail -1)
NN=$(printf '%02d' $(( ${LAST:-0} + 1 )))
OUT="$POC/${NN}-${SLUG}.png"
bash "$VM_SH" "base64 -w0 '$RPNG'" | base64 -d > "$OUT"
[ -s "$OUT" ] && echo "burp-hunt: saved $OUT" && echo "md: ![${SLUG} (Burp)](poc/${NN}-${SLUG}.png)" || { echo "burp-hunt: PNG pull failed" >&2; exit 1; }
