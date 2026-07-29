#!/usr/bin/env bash
# browser.sh - run a debuggable chromium and expose its CDP endpoint on loopback here,
# so `chrome-devtools-mcp --browserUrl http://127.0.0.1:<port>` can drive it.
#
#   bash scripts/browser.sh start              # kali (default): headless, has the VPN route
#   bash scripts/browser.sh start --host windows   # Windows Chrome, interactive (see below)
#   bash scripts/browser.sh status
#   bash scripts/browser.sh stop
#
# WHY A TUNNEL, NOT AN OPEN PORT: a DevTools port is UNAUTHENTICATED, total control of the
# browser - read any page, lift session cookies, drive authenticated apps. So chromium binds
# it to 127.0.0.1 ON KALI, and we forward loopback->loopback over SSH. The port is never
# offered to the LAN. Never "fix" a connection problem by binding 0.0.0.0.
#
# WHY KALI BY DEFAULT: same reason scripts/shot.py renders there - Kali holds the VPN route to
# in-scope targets. A browser on Windows/WSL cannot reach them.
#
# --host windows requires WSL mirrored networking (`networkingMode=mirrored` in .wslconfig +
# `wsl --shutdown`); under default NAT, Windows loopback is unreachable from WSL and the only
# alternative would be exposing the port. The script detects this and refuses rather than
# talking you into an open port.
set -uo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
VM_SH="${VM_SH:-/root/vm.sh}"
CREDS="${VM_CREDS:-/root/creds.txt}"
STATE_DIR="${CLAUDEBRAIN_BROWSER_STATE:-/tmp/claudebrain-browser}"
PORT=9222
HOST_MODE=kali
HEADED=0
TMUX_SESSION=browser
TMUX_WINDOW=cdp

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

CMD="${1:-}"; shift 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --host)   HOST_MODE="${2:-kali}"; shift 2;;
    --port)   PORT="${2:-9222}"; shift 2;;
    --headed) HEADED=1; shift;;
    -h|--help) usage 0;;
    *) echo "browser.sh: unknown arg '$1'" >&2; usage 2;;
  esac
done
case "$HOST_MODE" in
  kali|windows) ;;
  *) echo "browser.sh: --host must be kali or windows (got '$HOST_MODE')" >&2; exit 2;;
esac
mkdir -p "$STATE_DIR"
PIDFILE="$STATE_DIR/tunnel.pid"
METAFILE="$STATE_DIR/meta"

# --- creds resolution: mirrors vm.sh so both agree on which VM they mean -------------
# (vm.sh is device-local and holds the same parser; keep the two in step if either changes.)
_field() {
  local labels="$1" header="$2" v=""
  v=$(grep -ioE "^[[:space:]]*(${labels})[[:space:]]*[:=][[:space:]]*[^[:space:]#]+" "$CREDS" 2>/dev/null \
        | head -1 | sed -E 's/^[^:=]*[:=][[:space:]]*//')
  if [ -z "$v" ] && [ -n "$header" ]; then
    v=$(awk -v h="$header" 'BEGIN{IGNORECASE=1}
          $0 ~ "^[[:space:]]*#[[:space:]]*"h"[[:space:]]*$" {want=1; next}
          want && $0 !~ /^[[:space:]]*#/ && $0 !~ /^[[:space:]]*$/ {gsub(/^[[:space:]]+|[[:space:]]+$/,"");print;exit}' "$CREDS")
  fi
  printf '%s' "$v"
}

_pick_vm() {   # -> "user host" on stdout, or empty
  [ -r "$CREDS" ] || return 1
  local u p ts lan h
  u=$(_field "username|user" "Username"); p=$(_field "password|pass" "Password")
  ts=$(_field "tailnet[[:space:]]*ip|tailscale[[:space:]]*ip|ts[[:space:]]*ip" "")
  lan=$(_field "kali[[:space:]]*ip|vm[[:space:]]*ip|ip" "IP")
  [ -n "$u" ] && [ -n "$p" ] || return 1
  for h in "$ts" "$lan"; do
    [ -n "$h" ] || continue
    if timeout 8 bash -c "exec 3<>/dev/tcp/$h/22" 2>/dev/null; then printf '%s %s' "$u" "$h"; return 0; fi
  done
  return 1
}

_cdp_up() {    # CDP answering on the local port?
  curl -fsS --max-time 4 "http://127.0.0.1:$PORT/json/version" 2>/dev/null
}

# --- kali -----------------------------------------------------------------------------
_start_kali() {
  command -v sshpass >/dev/null || { echo "browser.sh: sshpass missing (vm.sh needs it too)" >&2; return 3; }
  local pair user host
  pair=$(_pick_vm) || { echo "browser.sh: no reachable VM in $CREDS (see docs/virtual-machine.md)" >&2; return 4; }
  user=${pair%% *}; host=${pair##* }
  echo "VM:   $user@$host"

  # chromium in a persistent tmux window, CDP bound to loopback ON THE VM.
  # --headless=new is the supported mode; --no-sandbox because the VM runs this as root.
  local flags="--remote-debugging-port=$PORT --remote-debugging-address=127.0.0.1 \
--user-data-dir=/tmp/cdp-profile --no-first-run --no-default-browser-check \
--no-sandbox --disable-dev-shm-usage --ignore-certificate-errors --window-size=1440,900"
  [ "$HEADED" = 1 ] || flags="--headless=new $flags"

  local remote="
tmux has-session -t $TMUX_SESSION 2>/dev/null || tmux new-session -d -s $TMUX_SESSION -n main -x 220 -y 50
WID=\"\$(tmux list-windows -t $TMUX_SESSION -F '#{window_id} #{window_name}' | awk '\$2==\"$TMUX_WINDOW\"{print \$1; exit}')\"
[ -n \"\$WID\" ] || WID=\"\$(tmux new-window -t $TMUX_SESSION -P -F '#{window_id}' -n $TMUX_WINDOW)\"
if curl -fsS --max-time 3 http://127.0.0.1:$PORT/json/version >/dev/null 2>&1; then
  echo 'remote: chromium already listening'
else
  tmux send-keys -t \"\$WID\" 'pkill -f remote-debugging-port=$PORT; chromium $flags about:blank' C-m
  for i in \$(seq 1 25); do
    curl -fsS --max-time 2 http://127.0.0.1:$PORT/json/version >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fsS --max-time 3 http://127.0.0.1:$PORT/json/version >/dev/null 2>&1 \
    && echo 'remote: chromium up' || { echo 'remote: chromium FAILED to open the port'; exit 1; }
fi"
  bash "$VM_SH" "$remote" || return 5

  # loopback -> loopback forward. -N: no remote command, this process is only the tunnel.
  # stdio MUST be detached: a background child holding the script's stdout keeps the pipe
  # open, so `browser.sh start | tail` would hang until killed instead of returning.
  local pass; pass=$(_field "password|pass" "Password")
  setsid sshpass -p "$pass" ssh -N -L "127.0.0.1:$PORT:127.0.0.1:$PORT" \
    -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
    -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
    "$user@$host" </dev/null >>"$STATE_DIR/tunnel.log" 2>&1 &
  local tpid=$!
  disown "$tpid" 2>/dev/null || true
  echo "$tpid" > "$PIDFILE"
  printf 'host=kali\nport=%s\nvm=%s@%s\ntunnel_pid=%s\n' "$PORT" "$user" "$host" "$tpid" > "$METAFILE"

  local i
  for i in $(seq 1 15); do _cdp_up >/dev/null && break; sleep 1; done
  if _cdp_up >/dev/null; then
    echo "CDP:  http://127.0.0.1:$PORT  (loopback only, via ssh -L, pid $tpid)"
    _cdp_up | head -c 200; echo
    return 0
  fi
  echo "browser.sh: tunnel up but CDP not answering on 127.0.0.1:$PORT" >&2
  kill "$tpid" 2>/dev/null; rm -f "$PIDFILE"
  return 6
}

# --- windows --------------------------------------------------------------------------
_start_windows() {
  local chrome="/mnt/c/Program Files/Google/Chrome/Application/chrome.exe"
  [ -f "$chrome" ] || chrome="/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
  [ -f "$chrome" ] || { echo "browser.sh: no Chrome/Edge found under /mnt/c" >&2; return 3; }

  # Under NAT networking, Windows loopback is NOT reachable from WSL. Refuse rather than
  # suggesting --remote-debugging-address=0.0.0.0, which would expose the browser to the LAN.
  if ! grep -qi 'networkingMode[[:space:]]*=[[:space:]]*mirrored' /mnt/c/Users/*/.wslconfig 2>/dev/null; then
    cat >&2 <<'EOF'
browser.sh: --host windows needs WSL mirrored networking.

  Under the default NAT mode Windows' 127.0.0.1 is a different loopback than WSL's, so the
  CDP port is unreachable from here. The only way around it without mirrored networking is
  binding the port to 0.0.0.0, which hands unauthenticated control of your browser -- and
  every session in it -- to anything on the LAN. This script will not do that.

  Enable it (one time), in C:\Users\<you>\.wslconfig:
      [wsl2]
      networkingMode=mirrored
  then from PowerShell:  wsl --shutdown     (restarts WSL; reopen your session afterwards)

  NOTE: mirrored mode changes WSL networking broadly. If you are mid-engagement with Ligolo
  tunnels up, finish that first.
EOF
    return 7
  fi

  "$chrome" --remote-debugging-port="$PORT" --user-data-dir='C:\Temp\cdp-mcp-profile' \
    --no-first-run --no-default-browser-check about:blank >/dev/null 2>&1 &
  printf 'host=windows\nport=%s\nchrome=%s\n' "$PORT" "$chrome" > "$METAFILE"
  local i; for i in $(seq 1 20); do _cdp_up >/dev/null && break; sleep 1; done
  if _cdp_up >/dev/null; then
    echo "CDP:  http://127.0.0.1:$PORT  (Windows Chrome, isolated profile - your real profile is untouched)"
    return 0
  fi
  echo "browser.sh: Chrome launched but CDP not answering on 127.0.0.1:$PORT" >&2
  return 6
}

case "$CMD" in
  start)
    if _cdp_up >/dev/null; then echo "already up: http://127.0.0.1:$PORT"; _cdp_up | head -c 200; echo; exit 0; fi
    case "$HOST_MODE" in
      kali)    _start_kali;;
      windows) _start_windows;;
    esac
    ;;
  status)
    if _cdp_up >/dev/null; then
      echo "UP    http://127.0.0.1:$PORT"
      [ -f "$METAFILE" ] && sed 's/^/      /' "$METAFILE"
      _cdp_up | head -c 300; echo
    else
      echo "DOWN  nothing answering on 127.0.0.1:$PORT"
      exit 1
    fi
    ;;
  stop)
    if [ -f "$PIDFILE" ]; then kill "$(cat "$PIDFILE")" 2>/dev/null && echo "tunnel stopped"; rm -f "$PIDFILE"; fi
    if [ -r "$CREDS" ] && grep -q '^host=kali' "$METAFILE" 2>/dev/null; then
      bash "$VM_SH" "pkill -f 'remote-debugging-port=$PORT'; tmux kill-window -t $TMUX_SESSION:$TMUX_WINDOW 2>/dev/null; true" \
        >/dev/null 2>&1 && echo "remote chromium stopped"
    fi
    rm -f "$METAFILE"
    ;;
  url) echo "http://127.0.0.1:$PORT";;
  -h|--help) usage 0;;
  "") usage 2;;
  *) echo "browser.sh: unknown command '$CMD'" >&2; usage 2;;
esac
