#!/usr/bin/env bash
# Leak check: scan every git-TRACKED file for client markers before sharing.
#
#   bash scripts/check-leaks.sh
#
# Client markers are the engagement directory names under targets/ (e.g. an
# "acme-corp" dir), derived automatically - the thing that must never appear in
# a shareable file. Optionally extend with targets/scrub-terms.txt for alternate
# client-identifying strings (codenames, alt domains). Do NOT add IP addresses
# or generic tool names (ligolo, wallix, nmap...) - they are not client data and
# only cause false positives.
#
# targets/ is git-ignored, so neither the engagement data nor the derived names
# are ever scanned/exposed; they only define what to look for elsewhere.
set -uo pipefail

VAULT="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
cd "$VAULT" || exit 1

# Optional single-file scan mode (the wiki-promote gate): scan ONE file against the
# same client-marker TERMS and exit 1 on any hit. Skips the git-tracked + advisory passes.
# --eng <name> is an orthogonal option (meaningful alongside --file): additionally
# derive scope-host markers from targets/<name>/scope.md - the candidate's OWN
# source_eng - on top of whichever engagement happens to be active (section 3
# below), so a candidate from engagement A is checked against A's scope even
# when a different engagement B is active.
SCAN_FILE=""
SCAN_ENG=""
if [ "${1:-}" = "--file" ]; then
  SCAN_FILE="${2:-}"
  # A bare --file with no path must fail loudly, not silently degrade to the
  # default tracked-file scan below (that would gate the wrong thing).
  [ -n "$SCAN_FILE" ] || { echo "FAIL: --file requires a path argument, e.g. --file <path>" >&2; exit 1; }
  if [ "${3:-}" = "--eng" ]; then
    SCAN_ENG="${4:-}"
    [ -n "$SCAN_ENG" ] || { echo "FAIL: --eng requires an engagement name argument" >&2; exit 1; }
  fi
fi

# 1. client names = engagement directory names under targets/
# Skip bare public CTF-platform names used as archive-folder names (targets/THM/,
# targets/HTB/, ...). Like tool names, these are NOT client data: a 3-letter term
# like a 3-letter platform tag matches that tag, its box-lesson mentions, and its
# source slugs all over the wiki, so it only produces false positives and makes the
# gate useless. Full per-box codenames (e.g. a "<platform>_<boxname>" dir) are NOT
# skipped - those ARE the client/engagement markers to catch.
PLATFORM_DENY=" thm htb pg tryhackme hackthebox provinggrounds proving-grounds vulnhub ctf pwk oscp htb-academy "
TERMS=()
if [ -d targets ]; then
  for d in targets/*/; do
    [ -d "$d" ] || continue
    name="$(basename "$d")"
    case "$name" in _templates|.*) continue;; esac
    lc="$(echo "$name" | tr '[:upper:]' '[:lower:]')"
    case "$PLATFORM_DENY" in *" $lc "*) continue;; esac
    TERMS+=("$name")
  done
fi

# 2. optional extra client-identifying strings (NOT IPs / tools)
EXTRA="targets/scrub-terms.txt"
if [ -f "$EXTRA" ]; then
  while IFS= read -r line; do
    line="$(echo "$line" | sed 's/[[:space:]]*#.*//' | xargs)"   # strip trailing comments
    [ -n "$line" ] && TERMS+=("$line")
  done < "$EXTRA"
fi

# 3. client hosts/domains from the active engagement's scope.md (derived at runtime,
#    never written to tracked files). Catches a client host leaked into a doc/skill,
#    not just the engagement dir name. Best-effort; silent if unavailable.
while IFS= read -r h; do
  [ -n "$h" ] && TERMS+=("$h")
done < <(python3 - <<'PY' 2>/dev/null
import sys
sys.path.insert(0, "skills/hooks")
try:
    import _engagement
    sc = _engagement.scope() or {}
    for k in ("in_scope", "out_of_scope"):
        for v in sc.get(k, []):
            v = (v or "").strip().lower()
            if v and "/" not in v and " " not in v and "." in v:   # host/domain-shaped only
                print(v)
except Exception:
    pass
PY
)

# 3b. optional: ALSO derive scope-host markers from a SPECIFIED engagement
#     (--eng), e.g. the wiki-promote gate passing the candidate's own
#     source_eng. Additive to section 3 above (never replaces it) - a candidate
#     staged from engagement A must be checked against A's scope even while a
#     different engagement B is active. Best-effort; silent if unavailable.
if [ -n "$SCAN_ENG" ]; then
  while IFS= read -r h; do
    [ -n "$h" ] && TERMS+=("$h")
  done < <(python3 - "$SCAN_ENG" <<'PY' 2>/dev/null
import os
import sys
sys.path.insert(0, "skills/hooks")
try:
    import _engagement
    d = os.path.join(_engagement.TARGETS, sys.argv[1])
    sc = _engagement.scope(d) or {}
    for k in ("in_scope", "out_of_scope"):
        for v in sc.get(k, []):
            v = (v or "").strip().lower()
            if v and "/" not in v and " " not in v and "." in v:   # host/domain-shaped only
                print(v)
except Exception:
    pass
PY
)
fi

if [ -n "$SCAN_FILE" ]; then
  # Fail closed: a missing/unreadable candidate must never read as clean.
  [ -r "$SCAN_FILE" ] || { echo "FAIL: candidate file not readable: $SCAN_FILE" >&2; exit 1; }
  if [ "${#TERMS[@]}" -eq 0 ]; then
    echo "clean: no client markers to check."
    exit 0
  fi
  fhits=0
  while IFS= read -r term; do
    [ -n "$term" ] || continue
    if grep -niIF "$term" "$SCAN_FILE" >/dev/null 2>&1; then
      echo "LEAK: client marker '$term' in candidate body."
      fhits=$((fhits + 1))
    fi
  done < <(printf '%s\n' "${TERMS[@]}" | sort -u)
  if [ "$fhits" -gt 0 ]; then
    echo "FAIL: $fhits client marker(s) in candidate body - not promotable."
    exit 1
  fi
  echo "clean: candidate body has no client markers (${#TERMS[@]} checked)."
  exit 0
fi

TMP="$(mktemp "${TMPDIR:-/tmp}/leakhits.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
if [ "${#TERMS[@]}" -eq 0 ]; then
  echo "No client names found (targets/ empty) - skipping marker scan."
else
  HITS=0
  while IFS= read -r term; do
    [ -n "$term" ] || continue
    # git grep only searches tracked files; targets/ is excluded explicitly too.
    if git grep -niIF "$term" -- . ':(exclude)targets/' >"$TMP" 2>/dev/null && [ -s "$TMP" ]; then
      echo "LEAK: client marker '$term' in tracked files:"
      sed 's/^/  /' "$TMP"
      HITS=$((HITS+1))
    fi
  done < <(printf '%s\n' "${TERMS[@]}" | sort -u)

  if [ "$HITS" -gt 0 ]; then
    echo ""
    echo "FAIL: $HITS client marker(s) leaked into tracked files. Scrub before sharing."
    exit 1
  fi
  echo "clean: no client markers (${#TERMS[@]} checked) in tracked files."
fi

# 4. generic high-signal WARN pass (advisory, never fails the gate): emails and
#    RFC1918 IPs in tracked files often mark a leaked host/contact. Review them.
echo ""
echo "advisory scan (review, not a hard fail):"
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
RFC1918_RE='\b(10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+)\b'
if git grep -nIE "$EMAIL_RE|$RFC1918_RE" -- . \
     ':(exclude)targets/' ':(exclude)wiki/payloads/' ':(exclude)tests/' ':(exclude)*example*' \
     >"$TMP" 2>/dev/null && [ -s "$TMP" ]; then
  sed 's/^/  WARN /' "$TMP"
  echo "  ^ emails/private IPs in tracked files - confirm none are client/personal before publishing."
else
  echo "  none."
fi

# 5. session boundary scan: session/ is gitignored (not tracked, so git grep above
#    skips it), but it MUST stay framework-only. Flag any client marker that leaked
#    into the generic, auto-loaded session/ files. Advisory (does not fail the gate).
echo ""
echo "session/ boundary scan (must stay framework-only):"
if [ -d session ] && [ "${#TERMS[@]}" -gt 0 ]; then
  shits=0
  while IFS= read -r term; do
    [ -n "$term" ] || continue
    if grep -rniIF "$term" session/ >"$TMP" 2>/dev/null && [ -s "$TMP" ]; then
      echo "  WARN client marker '$term' in session/ (move narrative to targets/<eng>/log.md):"
      sed 's/^/    /' "$TMP" | head -5
      shits=$((shits + 1))
    fi
  done < <(printf '%s\n' "${TERMS[@]}" | sort -u)
  [ "$shits" -eq 0 ] && echo "  clean: session/ is framework-only."
else
  echo "  (no session/ dir or no markers)"
fi
exit 0
