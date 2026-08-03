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

# ONE tmux session per PROGRAM, one window per tool PER HOST. A multi-site engagement is stored as
# <program>/<site>, so the session is the leading path segment and the host goes in the window name.
# Without this, each site got its own session and recon scattered across many sessions (the exact
# failure ctf-box warns about); with it, every scan for the program lands in one reviewable place.
SESSION="${ENG%%/*}"
HOSTSLUG="$(printf '%s' "$HOST" | tr './: ' '----')"

_roe(){ grep -qiE "^[[:space:]]*$1:[[:space:]]*true" "$SCOPE" 2>/dev/null; }
PASSIVE=0; NODOS=0
_roe passive_only && PASSIVE=1
_roe no_dos && NODOS=1

# Browser identity: a stock scanner User-Agent draws a blanket edge 403 on a WAF-fronted estate, so
# every ACTIVE launch carries a real desktop Chrome UA + a matching Accept-Language. Defined once here.
# QUOTING: vm-scan.sh wraps the whole scan command in SINGLE quotes for tmux send-keys, so a single
# quote inside a header value would terminate it early. Header values use ESCAPED DOUBLE quotes
# (\"...\"), which survive that wrapping intact. Do not "tidy" them into single quotes.
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
AL='lt-LT,lt;q=0.9,en;q=0.8'

# no_dos caps the RATE; it does NOT disable discovery. A scope.md that sets no_dos still explicitly
# permits "targeted scanners at low rate: nuclei, ffuf, ...". Only passive_only turns the active leg
# off. The low cap is deliberate: a mid-range rate has been observed to trip WAF wholesale-blocking,
# turning a whole run into identical block pages that no size filter can separate.
if [ "$NODOS" -eq 1 ]; then FFUF_RATE=5; NUCLEI_RL=10; else FFUF_RATE=40; NUCLEI_RL=150; fi

WL_LOCAL='scripts/wordlists/sensitive-artifacts.txt'
WL_FALLBACK='/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'

_launch(){ # <window> <scan-cmd>
  if [ "${RECON_WEB_DRYRUN:-0}" = "1" ]; then
    printf 'recon-web: %s -> %s\n' "$1-$HOSTSLUG" "$2"
  else
    bash scripts/vm-scan.sh --win "$1-$HOSTSLUG" "$SESSION" "$HOST" "$2"
  fi
}

# Render the LIVE page into poc/ via the harness chromium render (capture.sh web) -- NOT a scan tab.
# A tmux-tab "render" only cards terminal text, not the rendered page; and `shot.py --web` was wrong
# (shot.py takes the URL positionally, there is no --web flag). capture.sh web renders via chromium on
# the VM and PULLS the PNG into targets/<eng>/poc/ (+ saves page source). Passive-safe -> always fire.
RENDER_SLUG="web-$(printf '%s' "$HOST" | tr './: ' '----')"
if [ "${RECON_WEB_DRYRUN:-0}" = "1" ]; then
  printf 'recon-web: render -> capture.sh web %s %s %s\n' "$ENG" "$RENDER_SLUG" "$URL"
else
  bash scripts/capture.sh web "$ENG" "$RENDER_SLUG" "$URL" >/dev/null 2>&1 &
fi
# whatweb fingerprint (passive-safe) -> its own tmux tab (carded by autocard)
_launch whatweb "whatweb -a3 '$URL'"

# active content/vuln discovery -> OFF only under passive_only; no_dos rate-caps it instead (above).
if [ "$PASSIVE" -eq 0 ]; then
  # our artifact list is pushed base64-in-command (same bridge trick as backup-sweep below, since
  # vm.sh forwards no stdin); falls back to seclists when the vault file is missing.
  # ffuf, not feroxbuster: feroxbuster is not installed on the VM, so that launch always failed.
  WL_B64="$(base64 -w0 "$WL_LOCAL" 2>/dev/null || true)"
  _launch ffuf "echo $WL_B64 | base64 -d > /tmp/sensitive-artifacts.txt; W=/tmp/sensitive-artifacts.txt; [ -s \"\$W\" ] || W=$WL_FALLBACK; mkdir -p /tmp/scans/$RENDER_SLUG; ffuf -u '$URL/FUZZ' -w \"\$W\" -H \"User-Agent: $UA\" -H \"Accept-Language: $AL\" -rate $FFUF_RATE -ac -o /tmp/scans/$RENDER_SLUG/ffuf.json -of json"
  _launch nuclei "mkdir -p /tmp/scans/$RENDER_SLUG; nuclei -u '$URL' -rl $NUCLEI_RL -H \"User-Agent: $UA\" -o /tmp/scans/$RENDER_SLUG/nuclei.txt"
  # backup-sweep: appends backup SUFFIXES to full source filenames (login.php.bak) -- ffuf's -x
  # cannot (it appends one ext to a base word). Pushed to the VM then run in its own tab.
  BS_B64="$(base64 -w0 scripts/backup-sweep.sh 2>/dev/null)"
  _launch bak "echo $BS_B64 | base64 -d > /tmp/backup-sweep.sh; bash /tmp/backup-sweep.sh '$URL'"
fi

echo "recon-web: launched for $URL (passive=$PASSIVE no_dos=$NODOS)"
