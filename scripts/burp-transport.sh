#!/usr/bin/env bash
# burp-transport.sh -- resolve which Burp MCP transport the skill should drive.
# Prints ONE word on stdout (native|bridge|down); all guidance goes to stderr.
#
# WHY: the native mcp__burp__* tools only attach at SESSION START (if the Kali VM
# was up then) and never auto-reconnect. When they are absent the model cannot tell
# "VM down" from "Burp closed"; this makes the fallback deterministic -- bridge if the
# SSH CLI answers, else down with the real recovery (restart the session, VM up first).
#
# The NATIVE check is a MODEL action (ToolSearch select:mcp__burp__...), not shell-
# reachable, so the skill exports BURP_NATIVE=1 when that search loaded the tools and
# this script honors it as the top branch. bridge/down it probes itself.
#
# Usage:
#   burp-transport.sh            # resolve + print the mode word (guidance on stderr)
#   burp-transport.sh --dry-run  # offline: never dial the bridge (native-or-down only)
set -uo pipefail
VAULT="${VAULT:-$(cd "$(dirname "$0")/.." && pwd)}"
VM_SH="${VM_SH:-/root/vm.sh}"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1

if [ "${BURP_NATIVE:-}" = "1" ]; then
  echo native
  echo "burp-transport: native mcp__burp__* tools present -- drive them directly (cleanest, no bridge quoting)." >&2
  exit 0
fi

if [ "$DRY" = 1 ]; then
  echo down
  echo "burp-transport(--dry-run): native not flagged and the bridge probe is skipped offline." >&2
  exit 3
fi

# bridge probe: push the CLI (idempotent) then ask it to list tools. A non-empty list
# means the VM + Burp + MCP Server BApp are all up.
cli_b64=$(base64 -w0 "$VAULT/scripts/burp-mcp-cli.py" 2>/dev/null || true)
tools=$(bash "$VM_SH" "echo '$cli_b64' | base64 -d > ~/burp-mcp-cli.py 2>/dev/null
python3 ~/burp-mcp-cli.py list 2>/dev/null" 2>/dev/null | grep -c . || true)

if [ "${tools:-0}" -gt 0 ] 2>/dev/null; then
  echo bridge
  echo "burp-transport: native absent but the SSH bridge answers ($tools tools) -- use scripts/burp-mcp-cli.py (per-call; batch requests, it wedges after ~1 call/session)." >&2
  exit 0
fi

echo down
cat >&2 <<'MSG'
burp-transport: Burp MCP unreachable (native tools absent AND the SSH bridge listed no tools).
Most likely the Kali VM was DOWN at session start, so the native mcp__burp__ server never attached
(it only connects at startup and does not auto-reconnect). Recovery:
  1) bring the VM up and start Burp with the MCP Server BApp (SSE on 127.0.0.1:9876), then
  2) RESTART this session so the native server re-attaches.
Use the bridge (scripts/burp-mcp-cli.py) only if a session restart is unacceptable.
MSG
exit 3
