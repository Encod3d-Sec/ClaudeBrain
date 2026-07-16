#!/usr/bin/env bash
# capture.sh <mode> <eng> <slug> [args] - unified live PoC-evidence capture on the Kali VM.
# Merges the former ev/req/tmux/burp shot scripts into one entrypoint. Every mode renders a
# PNG on the VM (via shot.py) and pulls it into targets/<eng>/poc/NN-<slug>.png (auto-numbered),
# then prints the walkthrough `md:` ref. Call it the MOMENT a step LANDS, not at the end.
#
# Modes:
#   ev   <eng> <slug> <request-url> <cmd-label> [logfile]   terminal card (cmd + url) from a tee'd log
#   req  <eng> <slug> [--] <curl-args...>                   real `curl -iv` request/response card
#   tmux <eng> <slug> <local-script.sh>                     run a script in a real tmux pane, grab the pane
#   burp <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]
#                                                           Burp Repeater request/response grab (via MCP)
#
# The VM bridge is $VM_SH (default /root/vm.sh); files cross it base64-in-command (no stdin).
set -euo pipefail

VAULT="$(cd "$(dirname "$0")/.." && pwd)"
VM_SH="${VM_SH:-/root/vm.sh}"

usage() {
  cat >&2 <<'U'
usage: capture.sh <mode> <eng> <slug> [args]
  ev   <eng> <slug> <request-url> <cmd-label> [logfile]
  req  <eng> <slug> [--] <curl-args...>
  tmux <eng> <slug> <local-script.sh>
  burp <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]
U
  exit 2
}

# Sets POC + NN + PNG globals: the next NN index for <eng>'s poc/ dir, for <slug>.
# 10# forces base-10 (08->09, not octal); empty poc/ -> 01.
_poc_target() {   # $1=eng $2=slug
  POC="$VAULT/targets/$1/poc"; mkdir -p "$POC"
  local last; last=$(ls "$POC" 2>/dev/null | grep -oE '^[0-9]{2}' | sort -n | tail -1 || true)
  NN=$(printf "%02d" $(( 10#${last:-00} + 1 ))); PNG="$NN-$2.png"
}

# Pull a rendered PNG off the VM into poc/ (base64 through the pipe, not the caller's context)
# and print the saved path + walkthrough ref. $ENG/$POC/$PNG are set by the caller.
_pull_and_report() {   # $1=remote-png-path $2=caption
  bash "$VM_SH" "base64 -w0 '$1' 2>/dev/null" | base64 -d > "$POC/$PNG"
  if [ -s "$POC/$PNG" ]; then
    echo "saved targets/$ENG/poc/$PNG"
    echo "md: ![$2](poc/$PNG)"
  else
    echo "capture($MODE): no PNG produced (VM unreachable? tee the step output first?)" >&2
    exit 1
  fi
}

# ev: terminal card showing BOTH the command and the request URL, from a log you tee'd on the VM.
mode_ev() {
  [ $# -ge 4 ] || { echo "usage: capture.sh ev <eng> <slug> <request-url> <cmd-label> [logfile]" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" URL="$3" CMD="$4" LOG="${5:-/tmp/poc/$2.log}"
  _poc_target "$ENG" "$SLUG"
  local B64; B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "mkdir -p /tmp/poc; echo '$B64' | base64 -d > /tmp/shot.py
python3 /tmp/shot.py --term '$LOG' --cmd \"$CMD\" --url-bar \"$URL\" -o /tmp/poc/$PNG" >&2
  _pull_and_report "/tmp/poc/$PNG" "$CMD"
}

# req: full-fidelity curl -iv request+response card. base64-wraps the remote script so a
# forged body (+ / = / & / quotes) survives SSH transport.
mode_req() {
  [ $# -ge 3 ] || { echo "usage: capture.sh req <eng> <slug> [--] <curl-args...>" >&2; exit 2; }
  ENG="$1"; local SLUG="$2"; shift 2
  [ "${1:-}" = "--" ] && shift
  [ $# -ge 1 ] || { echo "capture(req): no curl args given" >&2; exit 2; }
  _poc_target "$ENG" "$SLUG"
  local LOG="/tmp/poc/$SLUG.reqresp" CURL="curl -sS -iv" a
  for a in "$@"; do CURL+=" $(printf '%q' "$a")"; done
  local REMOTE; REMOTE=$(cat <<EOF
mkdir -p /tmp/poc
{ echo "\$ $CURL"; echo; $CURL ; } > "$LOG" 2>&1 || true
EOF
)
  local RB64 SHOT_B64
  RB64=$(printf '%s' "$REMOTE" | base64 -w0)
  SHOT_B64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOT_B64' | base64 -d > /tmp/shot.py
echo '$RB64' | base64 -d > /tmp/reqshot_cmd.sh
bash /tmp/reqshot_cmd.sh
python3 /tmp/shot.py --term '$LOG' --reqresp --cmd 'curl -iv  (request + response)' --maxlines 600 -o /tmp/poc/$PNG" >&2
  _pull_and_report "/tmp/poc/$PNG" "curl request+response - $SLUG"
}

# tmux: run a command-script in a real Kali tmux pane and grab the pane, so the evidence is an
# ACTUAL session (real commands + output). The script should echo `# comments`/`$ cmds`, run
# them, and end with `echo POC-DONE`.
mode_tmux() {
  [ $# -ge 3 ] || { echo "usage: capture.sh tmux <eng> <slug> <local-script.sh>" >&2; exit 2; }
  ENG="$1"; local SLUG="$2" SCRIPT="$3"
  [ -f "$SCRIPT" ] || { echo "capture(tmux): no such script $SCRIPT" >&2; exit 2; }
  _poc_target "$ENG" "$SLUG"
  local SESS="poc_${SLUG//[^a-zA-Z0-9]/_}" SB64 SHOTB64
  SB64=$(base64 -w0 "$SCRIPT")
  SHOTB64=$(base64 -w0 "$VAULT/scripts/shot.py")
  bash "$VM_SH" "echo '$SHOTB64' | base64 -d > /tmp/shot.py
mkdir -p /tmp/poc; echo '$SB64' | base64 -d > /tmp/$SESS.sh; chmod +x /tmp/$SESS.sh
tmux kill-session -t $SESS 2>/dev/null || true
tmux new-session -d -s $SESS -x 200 -y 200
tmux set-option -t $SESS window-size manual 2>/dev/null || true
tmux resize-window -t $SESS -x 200 -y 200 2>/dev/null || true
tmux send-keys -t $SESS 'clear; bash /tmp/$SESS.sh' C-m
for i in \$(seq 1 60); do tmux capture-pane -p -t $SESS 2>/dev/null | grep -q POC-DONE && break; sleep 1; done
python3 /tmp/shot.py --tmux $SESS --reqresp --history --maxlines 100000 -o /tmp/poc/$PNG >/dev/null 2>&1
tmux kill-session -t $SESS 2>/dev/null || true" >&2
  _pull_and_report "/tmp/poc/$PNG" "$SLUG"
}

# burp: drive Burp (via the MCP) to replay a request in Repeater, then screenshot the
# request+response panes. Grabs as the SEAT user (Burp draws on the seat X session).
mode_burp() {
  [ $# -ge 7 ] || { echo "usage: capture.sh burp <eng> <slug> <host> <port> <https> <method> <path> [bodyfile] [tabname]" >&2; exit 2; }
  ENG=$1; local SLUG=$2 HOST=$3 PORT=$4 HTTPS=$5 METHOD=$6 RPATH=$7 BODYFILE=${8:-} TABNAME=${9:-$2}
  _poc_target "$ENG" "$SLUG"
  local RPNG="/tmp/burpshot_${SLUG//[^a-zA-Z0-9]/_}.png"

  # --- VM-side helper 1: build the raw request (CRLF) + create the Repeater tab via the MCP ---
  local TABPY GRABSH
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

  # --- VM-side helper 2: send in the GUI (as the seat user) + grab the window ---
  read -r -d '' GRABSH <<PY || true
set -e
U=\$(who | awk '/\\(:[0-9]/{print \$1; exit}'); U=\${U:-\$(who | awk 'NR==1{print \$1}')}
D=\$(who | grep -oE '\\(:[0-9]+' | head -1 | tr -d '('); D=\${D:-:0}
XA=/home/\$U/.Xauthority
r(){ sudo -u "\$U" env DISPLAY="\$D" XAUTHORITY="\$XA" "\$@"; }
WID=\$(r xdotool search --name "Burp Suite Professional" | head -1)
[ -n "\$WID" ] || { echo "GRAB_FAIL no Burp window on \$D"; exit 0; }
r xdotool windowactivate --sync "\$WID"; r xdotool windowraise "\$WID"; sleep 0.7
# window client origin, for coord mapping (screen = window + origin)
GEO=\$(r xdotool getwindowgeometry "\$WID"); WX=\$(echo "\$GEO" | awk -F'[ ,]+' '/Position/{print \$3}'); WY=\$(echo "\$GEO" | awk -F'[ ,]+' '/Position/{print \$4}'); WX=\${WX:-0}; WY=\${WY:-0}
# interactivity precheck: a headless/unmapped X still lets 'import' grab the window PIXMAP but routes
# INPUT to root, so clicks/keys never reach Burp (getmouselocation over Burp reports window:0). Fail loud.
UW=\$(r xdotool mousemove \$((WX+600)) \$((WY+300)) getmouselocation 2>/dev/null | grep -oE 'window:[0-9]+' | cut -d: -f2)
if [ "\${UW:-0}" = "0" ]; then echo "GRAB_FAIL Burp window not interactive (input routes to root - headless/unmapped display). Foreground Burp on the VM desktop or restart the X session, then retry."; exit 0; fi
# Java/Swing IGNORES synthetic --window (XSendEvent) input -> use XTEST (no --window). create_repeater_tab
# appends a tab but does NOT bring the Repeater tool to front, so a grab without this switch shows the last
# active tool (often the MCP tab). Caveat: it also does not auto-select the NEW sub-tab; run against a clean
# Repeater (or select the target tab first) so the active tab is the one just created.
r xdotool key ctrl+shift+r; sleep 1.2                                   # -> Repeater tool
r xdotool mousemove \$((WX+350)) \$((WY+400)) click 1; sleep 0.4         # focus the request editor
r xdotool key --clearmodifiers ctrl+space; sleep 4                      # Burp Repeater "Send"
r import -window "\$WID" "$RPNG"; chmod 644 "$RPNG" 2>/dev/null || true
echo "GRAB_OK \$WID"
PY

  local TABPY_B64 GRABSH_B64 CLI_B64
  TABPY_B64=$(printf '%s' "$TABPY" | base64 -w0)
  GRABSH_B64=$(printf '%s' "$GRABSH" | base64 -w0)
  CLI_B64=$(base64 -w0 "$VAULT/scripts/burp-mcp-cli.py")

  # 1) create the Repeater tab
  local RES
  RES=$(bash "$VM_SH" "echo '$CLI_B64' | base64 -d > ~/burp-mcp-cli.py
echo '$TABPY_B64' | base64 -d > /tmp/burpshot_tab.py
python3 /tmp/burpshot_tab.py '$HOST' '$PORT' '$HTTPS' '$METHOD' '$RPATH' '$TABNAME' '${BODYFILE}'" 2>&1 || true)
  if ! echo "$RES" | grep -q TAB_OK; then
    echo "capture(burp): create_repeater_tab failed -> $RES" >&2
    echo "  The Burp MCP SSE server wedges after the first call in a session. Restart the MCP Server" >&2
    echo "  BApp in Burp (the 'MCP' tab -> toggle the server off/on) and retry, or route via the proxy." >&2
    exit 1
  fi

  # 2) send + grab (seat user)
  bash "$VM_SH" "echo '$GRABSH_B64' | base64 -d > /tmp/burpshot_grab.sh; bash /tmp/burpshot_grab.sh" >&2

  # 3) pull the PNG into the vault poc/
  _pull_and_report "$RPNG" "$SLUG (Burp)"
}

MODE="${1:-}"; [ -n "$MODE" ] || usage
shift || true
case "$MODE" in
  ev)   mode_ev "$@" ;;
  req)  mode_req "$@" ;;
  tmux) mode_tmux "$@" ;;
  burp) mode_burp "$@" ;;
  -h|--help|help) usage ;;
  *)    echo "capture: unknown mode '$MODE'" >&2; usage ;;
esac
