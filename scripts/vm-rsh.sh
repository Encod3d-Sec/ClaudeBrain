#!/usr/bin/env bash
# Run ONE command in an engagement's reverse-shell tmux tab and return its clean output.
#
# Fixes the recurring drift of hand-driving a reverse shell with `tmux send-keys` +
# `capture-pane` and losing turns to shell-quoting (base64 wrappers, nested quotes). The
# command is base64-wrapped (so ANY quoting/metachars survive the vm.sh -> ssh -> tmux
# bridge), run between unique markers in the shell tab, and only the output between the
# markers is returned.
#
# Usage: bash vm-rsh.sh [--win shell] [--timeout 40] <session> <command...>
#   bash vm-rsh.sh <eng> 'strings /srv/x | grep -i clearance'
#   bash vm-rsh.sh --win shell <eng> 'cat /root/root.txt'
#
# Assumes a reverse shell is already live in tmux window <session>:<win> (default 'shell',
# the window scripts/vm-scan.sh --win shell created for the nc listener). VM_SH overridable
# for tests. Fail-soft: prints nothing + exits 1 if the end marker never appears.
set -uo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"
WIN="shell"; TO=40
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --win) WIN="${2:?--win needs a name}"; shift 2;;
    --timeout) TO="${2:?--timeout needs seconds}"; shift 2;;
    *) break;;
  esac
done
SESSION="${1:?need <session>}"; shift
CMD="$*"; : "${CMD:?need <command...>}"

# Fixed markers: a real command will not emit these; the extractor takes the LAST pair, so a
# prior run's markers still in scrollback do not confuse it.
# ponytail: fixed markers (not per-run random) so the output is trivially testable; the
# rfind-last-pair extraction covers the scrollback-collision ceiling.
START='__RSH_START_9f3a__'; END='__RSH_END_9f3a__'
B64="$(printf '%s' "$CMD" | base64 | tr -d '\n')"
SEND="echo $START; echo $B64 | base64 -d | bash 2>&1; echo $END"

# send the wrapped command into the shell tab
bash "$VM_SH" "tmux send-keys -t $SESSION:$WIN '$SEND' Enter" >/dev/null 2>&1

# poll the pane until the end marker shows up (or timeout)
PANE=""
for _ in $(seq 1 "$TO"); do
  PANE="$(bash "$VM_SH" "tmux capture-pane -pS -600 -t $SESSION:$WIN" 2>/dev/null)"
  printf '%s' "$PANE" | grep -qF "$END" && break
  sleep 1
done

# extract output between the LAST start marker and its end marker (drops the echoed cmd line)
printf '%s' "$PANE" | python3 -c '
import sys
t = sys.stdin.read()
s, e = "'"$START"'", "'"$END"'"
i = t.rfind(s); j = t.rfind(e)
if i < 0 or j <= i:
    sys.exit(1)
lines = t[i+len(s):j].split("\n")
while lines and not lines[0].strip():   # trim leading blanks (after the echo-output marker)
    lines.pop(0)
while lines and not lines[-1].strip():   # trim trailing blanks
    lines.pop()
if lines and (s in lines[0] or "base64 -d | bash" in lines[0]):  # safety: drop an echoed cmd line
    lines.pop(0)
print("\n".join(lines))
'
