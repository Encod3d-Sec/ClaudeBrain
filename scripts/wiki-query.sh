#!/usr/bin/env bash
# wiki-query.sh "<query>" [-k|--keyword] [-n N] - deterministic wiki-first fallback.
#
# The `wiki-search` MCP has dropped mid-session on multiple engagements; when it does, the
# wiki-first discipline must NOT silently degrade to ad-hoc grep. This wraps the SAME qmd
# index the MCP uses (qmd query = semantic, qmd keyword = substring), so a wiki-first lookup
# always has a working path from the Bash tool:
#
#   bash scripts/wiki-query.sh "jenkins rce exploit"       # semantic
#   bash scripts/wiki-query.sh -k "CVE-2023-23752"         # exact keyword (semantic misses IDs)
#
# Semantic first; auto-falls back to keyword when semantic returns nothing. Fails loud (with a
# grep fallback hint) if qmd is not installed. QMD_VAULT defaults to the vault root.
set -uo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
export QMD_VAULT="${QMD_VAULT:-$VAULT}"
export HF_HUB_DISABLE_PROGRESS_BARS=1     # silence the model-load progress noise

if ! command -v qmd >/dev/null 2>&1; then
  echo "wiki-query: qmd not installed (setup/bootstrap.sh installs it)." >&2
  echo "  fallback: grep -rin '<term>' wiki/   (then Read the matching page)" >&2
  exit 1
fi

N=5; KEYWORD=0; ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -k|--keyword) KEYWORD=1; shift;;
    -n) N="${2:-5}"; shift 2;;
    *) ARGS+=("$1"); shift;;
  esac
done
Q="${ARGS[*]:-}"
[ -n "$Q" ] || { echo "usage: wiki-query.sh \"<query>\" [-k|--keyword] [-n N]" >&2; exit 2; }

# qmd's BM25 subcommand is `search` on current builds and was `keyword` on older
# ones. Probe the help text: hardcoding either name means a rename silently turns
# every keyword lookup into "no results" -- the exact degradation this wrapper exists
# to prevent (it used to `qmd keyword ... 2>/dev/null; exit 0`, which swallowed
# "Unknown command: keyword" and reported success with empty output).
KW=search
qmd --help 2>/dev/null | grep -qE '^[[:space:]]*qmd search ' || KW=keyword

keyword_search() {
  local out rc
  out="$(qmd "$KW" "$Q" -n "$N" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ] || printf '%s\n' "$out" | grep -qi 'unknown command'; then
    echo "wiki-query: 'qmd $KW' failed -- qmd CLI changed?" >&2
    printf '%s\n' "$out" >&2
    echo "  fallback: grep -rin '$Q' wiki/   (then Read the matching page)" >&2
    return 1
  fi
  printf '%s\n' "$out"
}

if [ "$KEYWORD" = 1 ]; then
  keyword_search
  exit $?
fi

out="$(qmd query "$Q" -n "$N" 2>/dev/null)"
# Result lines are `qmd://<collection>/<path>` on current builds and `[score] path`
# on older ones. Accept either before concluding semantic came back empty.
if printf '%s\n' "$out" | grep -qE '^(qmd://|\[)'; then
  printf '%s\n' "$out"
else
  echo "wiki-query: semantic returned nothing -> keyword fallback" >&2
  keyword_search
fi
