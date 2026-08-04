#!/usr/bin/env bash
# backup-sweep.sh -- find dev-leaked SOURCE backups that feroxbuster structurally cannot.
#
# WHY THIS EXISTS: feroxbuster's `-x bak` appends ONE extension to a base WORD (login -> login.bak),
# so it never requests login.php.bak -- a backup SUFFIX on a full filename. Source-leak backups are
# almost always `<realfile>.<suffix>` (login.php.bak, config.php~, db.php.old). This sweep appends
# backup suffixes to full web-source filenames (a common seed + any discovered files) and filters the
# soft-404 baseline (apps that 200 every path). A single .php.bak = the whole app's source + creds.
#
# Usage:
#   backup-sweep.sh <base-url> [discovered-paths-file]
#   BURP_PROXY=127.0.0.1:8080 backup-sweep.sh http://T/     # route via Burp so it lands in Proxy history
#   backup-sweep.sh --dry-run <base-url> [paths-file]        # print the URLs it would probe (offline check)
set -uo pipefail
DRY=0; [ "${1:-}" = "--dry-run" ] && { DRY=1; shift; }
URL="${1:?usage: backup-sweep.sh [--dry-run] <base-url> [discovered-paths-file]}"; URL="${URL%/}"
EXTRA="${2:-}"

# ONE curl invocation shared by the baseline and every probe.
#  -A browser UA + Accept-Language: a stock `curl/8.x` UA draws a blanket edge 403 on a WAF/CDN
#     -fronted estate, and every probe then comes back 403 -- indistinguishable from "no backups
#     here" in the old output. Same UA recon-web.sh sends its scanners for the same reason.
#  -k: a self-signed / mismatched origin cert otherwise fails every request as code 000.
#  --connect-timeout / --max-time: this loop is SERIAL over ~1200 probes, so one hung request used
#     to stall the whole sweep (the tab never finishes, nothing is ever reported).
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
CURL=(curl -s -k --connect-timeout 5 --max-time 15 -A "$UA" -H 'Accept-Language: en-US,en;q=0.9')
[ -n "${BURP_PROXY:-}" ] && CURL+=(-x "${BURP_PROXY}")

# common server-side source files backups cluster around (with their REAL extension):
BASES="index.php index.html login.php dashboard.php config.php config.inc.php configuration.php
db.php database.php connect.php conn.php credentials.php secrets.php auth.php login_api.php
functions.php header.php footer.php search.php upload.php upload_profile.php admin.php api.php
api_login.php verify_otp.php otp.php import_feed_api.php register.php signup.php home.php user.php
users.php profile.php account.php settings.php init.php includes.php include.php app.php main.php
logout.php reset.php forgot.php"
# whole-site archives: the other half of the dev-leak class, and the half the base list above cannot
# reach (these carry no source extension, so they only pair with the archive suffixes below:
# backup + .zip, www + .tar.gz). One of these IS the entire application plus its config.
BASES="$BASES backup backups site www web html public_html source src app archive db dump database"
# fold in any discovered source files (php/js/asp/jsp/py/rb/inc/cgi/pl) from a ferox/paths file:
if [ -n "$EXTRA" ] && [ -f "$EXTRA" ]; then
  DISC="$(grep -oiE '[a-z0-9_./-]+\.(php|phtml|js|aspx?|jsp|py|rb|inc|cgi|pl)' "$EXTRA" 2>/dev/null \
          | sed 's#^https\?://[^/]*##; s#^/##; s#?.*$##' | sort -u)"
  BASES="$BASES $DISC"
fi
# backup / editor-swap / archive suffixes appended to each full filename (bases already carry their
# real extension, so login.php + .bak = login.php.bak -- exactly what feroxbuster -x cannot produce):
SUF=".bak .back .bak2 .old .old2 .save .swp .swo .orig .original .copy .tmp .temp ~ .1 .2 .txt .text
.zip .tar .tar.gz .tgz .gz .rar .7z _bak .dev .disabled .DISABLED"

BASES="$(printf '%s\n' $BASES | sort -u)"
if [ "$DRY" = "1" ]; then
  for b in $BASES; do for s in $SUF; do echo "$URL/$b$s"; done; done
  exit 0
fi

# soft-404 baseline: an app may 200 every unknown path (this is exactly why status alone is useless).
RAND="zzz$(head -c99 /dev/urandom 2>/dev/null | tr -dc a-z0-9 | head -c8)zz.php"
# No `|| echo` fallback: curl writes the -w format even when the request fails (000 0), so a
# fallback only appended a SECOND pair and left the size reading "0000 -1".
read -r bcode B < <("${CURL[@]}" -o /dev/null -w '%{http_code} %{size_download}\n' "$URL/$RAND" 2>/dev/null)
NB=$(printf '%s\n' $BASES | grep -c .); NS=$(printf '%s\n' $SUF | grep -c .)
echo "[*] backup-sweep $URL  soft-404 baseline=${bcode}/${B}b  probes=$((NB*NS))  (bases=$NB x suffixes=$NS)"
found=0
declare -A CODES=()
for b in $BASES; do for s in $SUF; do
  p="$b$s"
  read -r code size < <("${CURL[@]}" -o /dev/null -w '%{http_code} %{size_download}\n' "$URL/$p" 2>/dev/null)
  code="${code:-000}"; size="${size:-0}"
  CODES[$code]=$(( ${CODES[$code]:-0} + 1 ))
  if [ "$code" = "200" ] && [ "$size" != "$B" ] && [ "${size:-0}" -gt 0 ] 2>/dev/null; then
    echo "[+] LEAK  $URL/$p  (${size}b)"; found=$((found+1))
  fi
done; done
# Status histogram: "found nothing" and "was blocked / never connected" produce identical LEAK output
# (none), so ALWAYS print what the server actually answered. A sweep that is 100% 403 or 000 proved
# nothing about this host and must not be recorded as a tested-and-clean vuln class.
echo "[*] status: $(for c in "${!CODES[@]}"; do printf '%s=%s ' "$c" "${CODES[$c]}"; done)"
blocked=$(( ${CODES[403]:-0} + ${CODES[406]:-0} + ${CODES[429]:-0} + ${CODES[503]:-0} + ${CODES[000]:-0} ))
if [ "$found" -eq 0 ] && [ "$blocked" -gt $(( NB * NS / 2 )) ]; then
  echo "[!] INCONCLUSIVE: most probes were blocked/unreachable (403/406/429/503/000), not answered."
  echo "    The edge is filtering this sweep -- treat backups as UNTESTED here, not clean."
  echo "    Retry through Burp (BURP_PROXY=127.0.0.1:8080) or from a browser-identity session."
  exit 0
fi
echo "[*] done: $found candidate backup(s). READ each in full -- source leak = creds/auth logic/hidden endpoints."
