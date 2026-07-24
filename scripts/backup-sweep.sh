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
PX=""; [ -n "${BURP_PROXY:-}" ] && PX="-x ${BURP_PROXY}"

# common server-side source files backups cluster around (with their REAL extension):
BASES="index.php index.html login.php dashboard.php config.php config.inc.php configuration.php
db.php database.php connect.php conn.php credentials.php secrets.php auth.php login_api.php
functions.php header.php footer.php search.php upload.php upload_profile.php admin.php api.php
api_login.php verify_otp.php otp.php import_feed_api.php register.php signup.php home.php user.php
users.php profile.php account.php settings.php init.php includes.php include.php app.php main.php
logout.php reset.php forgot.php"
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
B=$(curl -s $PX -o /dev/null -w '%{size_download}' "$URL/$RAND" 2>/dev/null || echo -1)
NB=$(printf '%s\n' $BASES | grep -c .); NS=$(printf '%s\n' $SUF | grep -c .)
echo "[*] backup-sweep $URL  soft-404 baseline=${B}b  probes=$((NB*NS))  (bases=$NB x suffixes=$NS)"
found=0
for b in $BASES; do for s in $SUF; do
  p="$b$s"
  read -r code size < <(curl -s $PX -o /dev/null -w '%{http_code} %{size_download}' "$URL/$p" 2>/dev/null || echo "000 0")
  if [ "$code" = "200" ] && [ "$size" != "$B" ] && [ "${size:-0}" -gt 0 ] 2>/dev/null; then
    echo "[+] LEAK  $URL/$p  (${size}b)"; found=$((found+1))
  fi
done; done
echo "[*] done: $found candidate backup(s). READ each in full -- source leak = creds/auth logic/hidden endpoints."
