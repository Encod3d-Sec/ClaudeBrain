#!/usr/bin/env bash
# burp-raw.sh -- send a RAW HTTP request (arbitrary headers, cookies, body) through Burp via MCP.
#
# WHY: burp-hunt.sh builds its own request line and hardcodes Accept/Connection, so it cannot carry a
# session cookie or a custom header. Authenticated testing needs the request verbatim.
#
#   bash scripts/burp/burp-raw.sh <rawfile-local> <host> <port> <https true|false>
#
# The raw file is a normal HTTP/1.1 request; LF or CRLF line endings both work (normalised to CRLF).
# Sends via Burp so the request lands in proxy history and the operator can watch and replay it.
set -uo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"
[ $# -ge 4 ] || { echo "usage: burp-raw.sh <rawfile> <host> <port> <https>" >&2; exit 2; }
RAW=$1; HOST=$2; PORT=$3; HTTPS=$4
[ -f "$RAW" ] || { echo "burp-raw: no such file: $RAW" >&2; exit 2; }

b64=$(base64 -w0 "$RAW")
bash "$VM_SH" "echo '$b64' | base64 -d > /tmp/burp-raw.req
python3 -c \"
import json, subprocess, os, sys
req = open('/tmp/burp-raw.req', 'rb').read().decode('utf-8', 'replace')
req = req.replace('\\r\\n', '\\n').rstrip('\\n').replace('\\n', '\\r\\n') + '\\r\\n\\r\\n'
args = json.dumps({'content': req, 'targetHostname': '$HOST', 'targetPort': $PORT, 'usesHttps': '$HTTPS' == 'true'})
p = subprocess.run(['python3', os.path.expanduser('~/burp-mcp-cli.py'), 'call', 'send_http1_request', args],
                   capture_output=True, text=True, timeout=90)
sys.stdout.write(p.stdout or p.stderr)
\""
