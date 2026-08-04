#!/usr/bin/env bash
# recon-web.sh <eng> <url> -- fan out the parallel web-recon suite on a discovered URL.
# Run BY HAND. Nothing auto-launches it any more: the web-recon.py hook that did was removed
# 2026-08-04 (it fired on tool OUTPUT, so merely printing a hostname relaunched scans + a page
# render against hosts already retired).
# Each tool gets its own tmux window (via vm-scan.sh) so scans run in parallel and get carded.
# RoE-aware from targets/<eng>/scope.md: passive_only or no_dos -> whatweb only (no ferox/nuclei).
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

# NO page render here. This used to fire `capture.sh web` (chromium render + page source into
# targets/<eng>/poc/) on every launch; it produced empty poc/ dirs instead of evidence and, being a
# side effect of scanning, scaffolded poc/ under host dirs that were already retired. Render
# deliberately, when a page is worth evidencing: `Skill(screenshot)` / `scripts/capture.sh web`.
# whatweb fingerprint (passive-safe) -> its own tmux tab (carded by autocard)
_launch whatweb "whatweb -a3 '$URL'"

# active content/vuln discovery -> gated by RoE
if [ "$PASSIVE" -eq 0 ] && [ "$NODOS" -eq 0 ]; then
  _launch ferox "W=$WL; [ -f \"\$W\" ] || W=/usr/share/wordlists/dirb/common.txt; feroxbuster -u '$URL' -w \"\$W\" -x php,txt,html,bak --no-state"
  _launch nuclei "nuclei -u '$URL'"
  # backup-sweep: appends backup SUFFIXES to full source filenames (login.php.bak) -- feroxbuster's -x
  # cannot (it appends one ext to a base word). Pushed to the VM then run in its own tab.
  BS_B64="$(base64 -w0 scripts/backup-sweep.sh 2>/dev/null)"
  _launch bak "echo $BS_B64 | base64 -d > /tmp/backup-sweep.sh; bash /tmp/backup-sweep.sh '$URL'"
fi

echo "recon-web: launched for $URL (passive=$PASSIVE no_dos=$NODOS)"
