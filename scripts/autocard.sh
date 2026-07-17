#!/usr/bin/env bash
# Auto-card FINISHED scan tmux tabs for an engagement into recon/ - the always-on half of live
# capture. Fired DETACHED from the Stop hook each turn, so it never blocks a turn and needs no LLM
# tokens: it just renders any scan tab that has finished since last time and isn't carded yet.
#
#   bash scripts/autocard.sh <engagement>
#
# Idempotent: each tab is carded once (tracked in targets/<eng>/.carded-tabs). Fail-open: any
# problem (no VM, no tmux session, no tabs) exits 0 silently. A tab still running is skipped this
# round and picked up on a later turn once its pane shows the shell prompt again.
ENG="${1:-}"; [ -n "$ENG" ] || exit 0
VAULT="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)" || exit 0
VM_SH="${VM_SH:-/root/vm.sh}"
D="$VAULT/targets/$ENG"; [ -d "$D" ] || exit 0
CARDED="$D/.carded-tabs"; touch "$CARDED" 2>/dev/null || true

LIST=$(bash "$VM_SH" "tmux list-windows -t '$ENG' -F '#{window_name}' 2>/dev/null" 2>/dev/null) || exit 0
[ -n "$LIST" ] || exit 0

# NOTE: read the tab list on fd 3, NOT stdin - the `bash $VM_SH` (ssh) calls inside the loop read
# stdin and would otherwise swallow the rest of the list, carding only the first window.
while IFS= read -r tab <&3; do
  [ -n "$tab" ] || continue
  case "$tab" in bash|main|0|zsh|sh) continue ;; esac         # skip the default session shell window
  grep -qxF "$tab" "$CARDED" 2>/dev/null && continue          # already carded once
  # finished? the pane's last non-empty line is a shell prompt (kali `└─#`, or a trailing #/$).
  last=$(bash "$VM_SH" "tmux capture-pane -t '$ENG:$tab' -p 2>/dev/null | grep -vE '^[[:space:]]*$' | tail -1" 2>/dev/null </dev/null)
  printf '%s' "$last" | grep -qE '└─#|[#$][[:space:]]*$' || continue   # still running -> next round
  slug=$(printf '%s' "$tab" | tr -cd 'A-Za-z0-9-' | cut -c1-24)
  if bash "$VAULT/scripts/capture.sh" recon "$ENG" "auto-$slug" "$tab" >/dev/null 2>&1 </dev/null; then
    printf '%s\n' "$tab" >> "$CARDED"
  fi
done 3<<< "$LIST"
exit 0
