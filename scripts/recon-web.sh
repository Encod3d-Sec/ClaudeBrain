#!/usr/bin/env bash
# recon-web.sh <eng> <url> -- fan out the parallel web-recon suite on a discovered URL.
# Auto-launched by the web-recon.py hook when a web surface is discovered; also runnable by hand.
# Each tool gets its own tmux window (via vm-scan.sh) so scans run in parallel and get carded.
# RoE-aware from targets/<eng>/scope.md: passive_only -> render+whatweb only; no_dos -> drop ferox+nuclei.
# RECON_WEB_DRYRUN=1 -> print the launches instead of running them (offline / testable).
set -u
ENG="${1:?usage: recon-web.sh <eng> <url>}"
URL="${2:?usage: recon-web.sh <eng> <url>}"
HOST="$(printf '%s' "$URL" | sed -E 's#^[a-z][a-z0-9+.-]*://##; s#[/:].*$##')"
SCOPE="targets/$ENG/scope.md"

_roe(){ grep -qiE "^[[:space:]]*$1:[[:space:]]*true" "$SCOPE" 2>/dev/null; }
PASSIVE=0; NODOS=0
_roe passive_only && PASSIVE=1
_roe no_dos && NODOS=1

WL='/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'

_launch(){ # <window> <scan-cmd>
  if [ "${RECON_WEB_DRYRUN:-0}" = "1" ]; then
    printf 'recon-web: %s -> %s\n' "$1" "$2"
  else
    bash scripts/vm-scan.sh --win "$1" "$ENG" "$HOST" "$2"
  fi
}

# render + fingerprint are passive-safe -> always fire
_launch render "command -v gowitness >/dev/null 2>&1 && gowitness single --screenshot-path /tmp '$URL' || python3 /opt/arsenal/shot.py --web '$URL'"
_launch whatweb "whatweb -a3 '$URL'"

# active content/vuln discovery -> gated by RoE
if [ "$PASSIVE" -eq 0 ] && [ "$NODOS" -eq 0 ]; then
  _launch ferox "W=$WL; [ -f \"\$W\" ] || W=/usr/share/wordlists/dirb/common.txt; feroxbuster -u '$URL' -w \"\$W\" -x php,txt,html,bak --no-state"
  _launch nuclei "nuclei -u '$URL'"
fi

echo "recon-web: launched for $URL (passive=$PASSIVE no_dos=$NODOS)"
