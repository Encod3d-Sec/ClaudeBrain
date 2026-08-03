#!/usr/bin/env bash
# Add generic tokens to a harness wordlist, deduped + sorted, with a leak-safe filter.
# Usage: scripts/wl-add.sh paths  internal customapi health
#        scripts/wl-add.sh params target host file
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WL="$HERE/wordlists"
kind="${1:-}"; shift || true
case "$kind" in
  paths)  file="$WL/harness-paths.txt";  re='^[a-z0-9][a-z0-9_./-]*$' ;;
  params) file="$WL/harness-params.txt"; re='^[a-z][a-z0-9_]*$' ;;
  ignore) file="$WL/.wl-ignore";         re='^[a-z0-9][a-z0-9_./-]*$' ;;   # suppress box-specific tokens from future suggestions
  *) echo "usage: wl-add.sh paths|params|ignore <word>..." >&2; exit 2 ;;
esac
[ $# -ge 1 ] || { echo "no words given" >&2; exit 2; }

# never accept a filesystem dir / sensitive name / IP-ish / overlong token
stop=" etc root var proc sys dev bin sbin lib lib64 mnt boot run passwd shadow group gshadow hosts hostname sudoers crontab "
added=0; skipped=0
for w in "$@"; do
  t="$(printf '%s' "$w" | tr 'A-Z' 'a-z' | sed 's#^/*##; s#/*$##')"
  if ! printf '%s' "$t" | grep -qE "$re"; then echo "skip (bad chars): $w" >&2; skipped=$((skipped+1)); continue; fi
  if [ ${#t} -gt 40 ]; then echo "skip (too long): $w" >&2; skipped=$((skipped+1)); continue; fi
  if printf '%s' "$t" | grep -qE '[0-9]{1,3}\.[0-9]{1,3}'; then echo "skip (IP-ish): $w" >&2; skipped=$((skipped+1)); continue; fi
  if printf '%s' " $stop " | grep -q " $t "; then echo "skip (fs/sensitive): $w" >&2; skipped=$((skipped+1)); continue; fi
  if grep -qxF "$t" "$file" 2>/dev/null; then continue; fi   # already present
  printf '%s\n' "$t" >> "$file"; added=$((added+1))
done

# dedup + sort in place (stable, unique, drop blanks)
sort -u -o "$file" <(grep -vE '^\s*$' "$file")
echo "wl-add: +$added new, $skipped skipped -> $file ($(wc -l < "$file") total)"
