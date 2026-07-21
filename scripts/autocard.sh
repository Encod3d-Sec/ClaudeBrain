#!/usr/bin/env bash
# Auto-card FINISHED scan tmux tabs for an engagement into recon/ - the always-on half of live
# capture. Run SYNCHRONOUSLY (bounded) from the Stop hook each turn: it renders any scan tab that has
# finished since last time and isn't carded yet. Bounded so it completes inside the hook window --
# a detached spawn was unreliable over the WSL/remote-VM SSH bridge (the grandchild often never ran,
# so cards only appeared in one late batch at close-out). Running it in-hook, capped to a couple of
# tabs per turn, makes cards trickle in live and deterministically.
#
#   bash scripts/autocard.sh <engagement>
#
# Env: AUTOCARD_MAX=N   cards at most N tabs per invocation (default 2, keeps a run short so it
#                       finishes well under the hook timeout; the rest are picked up next turn).
#      CAPTURE_SH=path  override the capture.sh used (test injection); default scripts/capture.sh.
#      VM_SH=path       the SSH bridge to the tooling VM (default /root/vm.sh).
# Idempotent: each tab is carded once (tracked in targets/<eng>/.carded-tabs). Fail-open: any
# problem (no VM, no tmux session, no tabs) exits 0 silently. A tab still running is skipped this
# round and picked up on a later turn once its pane shows the shell prompt again.
ENG="${1:-}"; [ -n "$ENG" ] || exit 0
VAULT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)" || exit 0
VM_SH="${VM_SH:-/root/vm.sh}"
CAP="${CAPTURE_SH:-$VAULT/scripts/capture.sh}"
MAX="${AUTOCARD_MAX:-2}"
# AUTOCARD_ALL=1 (close-out sweep, fired by build-walkthrough.py): drop the per-run cap AND card
# EVERY not-yet-carded tab regardless of whether its pane shows a finished prompt. Long-running
# scans (ferox/nuclei) and never-finishing listener tabs (http.server / nc / a live shell) are
# valid evidence at close-out, but the finished-prompt gate below would skip them forever - so a
# fast box ends with those tabs uncarded. The end-of-box sweep closes that gap.
ALL="${AUTOCARD_ALL:-}"; [ -n "$ALL" ] && MAX=100000
D="$VAULT/targets/$ENG"; [ -d "$D" ] || exit 0
CARDED="$D/.carded-tabs"; touch "$CARDED" 2>/dev/null || true

# Bound every SSH round-trip so ONE hung call is skipped and the run still cards the good tabs.
# Keep this per-call cap SHORTER than the caller's total budget (close-out.py runs us under
# `timeout=8`), or the caller hard-kills the whole run before this guard can fire. Fail-open if
# `timeout` is absent.
TO="timeout 5"; command -v timeout >/dev/null 2>&1 || TO=""

LIST=$($TO bash "$VM_SH" "tmux list-windows -t '$ENG' -F '#{window_name}' 2>/dev/null" 2>/dev/null) || exit 0
[ -n "$LIST" ] || exit 0

# NOTE: read the tab list on fd 3, NOT stdin - the `bash $VM_SH` (ssh) calls inside the loop read
# stdin and would otherwise swallow the rest of the list, carding only the first window.
n=0
while IFS= read -r tab <&3; do
  [ "$n" -ge "$MAX" ] && break                                 # per-run cap -> short run, cards trickle in
  [ -n "$tab" ] || continue
  case "$tab" in bash|main|0|zsh|sh) continue ;; esac         # skip the default session shell window
  grep -qxF "$tab" "$CARDED" 2>/dev/null && continue          # already carded once
  # finished? the pane's last non-empty line is a shell prompt (kali `└─#`, or a trailing #/$).
  # AUTOCARD_ALL (close-out sweep) skips this gate so still-running / listener tabs are still carded.
  if [ -z "$ALL" ]; then
    last=$($TO bash "$VM_SH" "tmux capture-pane -t '$ENG:$tab' -p 2>/dev/null | grep -vE '^[[:space:]]*$' | tail -1" 2>/dev/null </dev/null)
    printf '%s' "$last" | grep -qE '└─#|[#$][[:space:]]*$' || continue   # still running -> next round
  fi
  slug=$(printf '%s' "$tab" | tr -cd 'A-Za-z0-9-' | cut -c1-24)
  if $TO bash "$CAP" recon "$ENG" "auto-$slug" "$tab" >/dev/null 2>&1 </dev/null; then
    printf '%s\n' "$tab" >> "$CARDED"
    n=$((n+1))
  fi
done 3<<< "$LIST"
exit 0
