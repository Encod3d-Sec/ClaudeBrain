#!/usr/bin/env bash
# burpshot.sh - drive Burp Suite (via the MCP) to replay a request in Repeater, then screenshot
# the request+response panes as a PoC image and pull it into targets/<eng>/poc/. Encapsulates the
# working flow so "using Burp" always yields the request/response image:
#   1. create_repeater_tab (Burp MCP) with the raw request
#   2. activate Burp on the SEAT display (:0) as the desktop user (Burp may be root-owned but it
#      draws on the seat user's X session -> grab as that user, with their .Xauthority)
#   3. focus the request editor + Ctrl+Space  (Burp's Repeater "Send" hotkey)
#   4. import-grab the Burp window to a WORLD-WRITABLE /tmp path (a root-owned -o dir makes the
#      sudo-as-seat-user grab fail with EACCES), then pull it into poc/
#
#   usage: burpshot <eng> <slug> <host> <port> <https:true|false> <method> <path> [bodyfile] [tabname]
#   e.g.:  burpshot thm_x flag1 10.1.1.1 5000 true  POST /login /tmp/login_body.txt "ECorp login"
#          burpshot thm_x flag3 10.1.1.1 3000 false GET  /challenge/solve
set -euo pipefail

[ $# -ge 7 ] || { echo "usage: burpshot <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]" >&2; exit 2; }
ENG=$1; SLUG=$2; HOST=$3; PORT=$4; HTTPS=$5; METHOD=$6; RPATH=$7; BODYFILE=${8:-}; TABNAME=${9:-$SLUG}
VAULT="$(cd "$(dirname "$0")/.." && pwd)"
POC="$VAULT/targets/$ENG/poc"; mkdir -p "$POC"
last=$(ls "$POC" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
NN=$(printf "%02d" $(( 10#${last:-00} + 1 ))); PNG="$NN-$SLUG.png"
RPNG="/tmp/burpshot_${SLUG//[^a-zA-Z0-9]/_}.png"

# --- VM-side helper 1: build the raw request (CRLF) + create the Repeater tab via the MCP -------
read -r -d '' TABPY <<'PY' || true
import json, os, subprocess, sys
cli = os.path.expanduser("~/burp-mcp-cli.py")
host, port, https, method, path, tab = sys.argv[1:7]
bf = sys.argv[7] if len(sys.argv) > 7 and sys.argv[7] else ""
lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s:%s" % (host, port), "Connection: close"]
body = ""
if bf:
    body = open(bf).read().strip()
    lines += ["Content-Type: application/x-www-form-urlencoded;charset=UTF-8", "Content-Length: %d" % len(body)]
req = "\r\n".join(lines + ["", body])
args = json.dumps({"content": req, "targetHostname": host, "targetPort": int(port),
                   "usesHttps": https == "true", "tabName": tab})
try:
    p = subprocess.run(["python3", cli, "call", "create_repeater_tab", args],
                       capture_output=True, text=True, timeout=45)
    print("TAB_OK" if "Executed" in p.stdout else "TAB_FAIL " + (p.stdout.strip() or p.stderr.strip()[-140:]))
except Exception as e:
    print("TAB_FAIL " + str(e))
PY

# --- VM-side helper 2: send in the GUI (as the seat user) + grab the window ---------------------
read -r -d '' GRABSH <<PY || true
set -e
U=\$(who | awk '/\\(:[0-9]/{print \$1; exit}'); U=\${U:-\$(who | awk 'NR==1{print \$1}')}
D=\$(who | grep -oE '\\(:[0-9]+' | head -1 | tr -d '('); D=\${D:-:0}
XA=/home/\$U/.Xauthority
r(){ sudo -u "\$U" env DISPLAY="\$D" XAUTHORITY="\$XA" "\$@"; }
WID=\$(r xdotool search --name "Burp Suite Professional" | head -1)
[ -n "\$WID" ] || { echo "GRAB_FAIL no Burp window on \$D"; exit 0; }
r xdotool windowactivate --sync "\$WID"; r xdotool windowraise "\$WID"; sleep 0.6
r xdotool mousemove 500 400; r xdotool click 1; sleep 0.4     # focus the request editor
r xdotool key --clearmodifiers ctrl+space; sleep 4           # Burp Repeater "Send"
r import -window "\$WID" "$RPNG"; chmod 644 "$RPNG" 2>/dev/null || true
echo "GRAB_OK \$WID"
PY

TABPY_B64=$(printf '%s' "$TABPY" | base64 -w0)
GRABSH_B64=$(printf '%s' "$GRABSH" | base64 -w0)
CLI_B64=$(base64 -w0 "$VAULT/scripts/burp-mcp-cli.py")

# 1) create the Repeater tab
RES=$(bash /root/vm.sh "echo '$CLI_B64' | base64 -d > ~/burp-mcp-cli.py
echo '$TABPY_B64' | base64 -d > /tmp/burpshot_tab.py
python3 /tmp/burpshot_tab.py '$HOST' '$PORT' '$HTTPS' '$METHOD' '$RPATH' '$TABNAME' '${BODYFILE}'" 2>&1 || true)
if ! echo "$RES" | grep -q TAB_OK; then
    echo "burpshot: create_repeater_tab failed -> $RES" >&2
    echo "  The Burp MCP SSE server wedges after the first call in a session. Restart the MCP Server" >&2
    echo "  BApp in Burp (the 'MCP' tab -> toggle the server off/on) and retry, or route via the proxy." >&2
    exit 1
fi

# 2) send + grab (seat user)
bash /root/vm.sh "echo '$GRABSH_B64' | base64 -d > /tmp/burpshot_grab.sh; bash /tmp/burpshot_grab.sh" >&2

# 3) pull the PNG into the vault poc/
bash /root/vm.sh "base64 -w0 '$RPNG' 2>/dev/null" | base64 -d > "$POC/$PNG"
if [ -s "$POC/$PNG" ]; then
    echo "saved targets/$ENG/poc/$PNG"
    echo "md: ![$SLUG (Burp)](poc/$PNG)"
else
    echo "burpshot: no PNG produced (Burp window not found / grab failed)" >&2
    exit 1
fi
