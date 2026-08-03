#!/usr/bin/env bash
# vm-sync.sh <name> - ensure /opt/arsenal/<name> exists on the Kali VM. If it is missing,
# base64-push it from the vault scripts/ dir (the vm.sh bridge forwards NO stdin, so we
# base64-into-the-command; see docs/virtual-machine.md). Idempotent, fails open with a
# clear message when the VM is unreachable. Use it before reaching for a helper on a box:
#   bash scripts/vm-sync.sh pspy64        # (once pspy64 is a file in scripts/)
#   bash scripts/vm-sync.sh shot.py
set -euo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"
ARSENAL="/opt/arsenal"

name="${1:-}"
[ -n "$name" ] || { echo "usage: vm-sync.sh <script-name-in-scripts/>" >&2; exit 1; }
src="$(cd "$(dirname "$0")" && pwd)/$name"
[ -f "$src" ] || { echo "vm-sync: $src not found in vault scripts/" >&2; exit 1; }

if bash "$VM_SH" "test -f $ARSENAL/$name && echo EXISTS" 2>/dev/null | grep -q EXISTS; then
  echo "vm-sync: $name already in $ARSENAL"
  exit 0
fi

b64="$(base64 -w0 "$src")"
bash "$VM_SH" "mkdir -p $ARSENAL && printf %s '$b64' | base64 -d > $ARSENAL/$name && chmod +x $ARSENAL/$name && echo SYNCED"
