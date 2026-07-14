#!/usr/bin/env bash
# vm.sh - one-line SSH bridge to the Kali attack VM. Device-local. No secrets in this file.
#
# Reads IP(s)/user/password from /root/creds.txt (git-ignored, per-device) and runs a
# command as the configured user on the VM, streaming output back. Cross-machine: it tries
# each candidate host in priority order (Tailscale/100.x IP first = location-independent,
# then the LAN/VM IP) and uses the first that answers on :22. So the SAME script works from
# any machine that can reach the VM by any of those addresses.
#
#   bash /root/vm.sh '<remote bash command>'
#   bash /root/vm.sh 'id; hostname; ip -4 addr'
#
# creds.txt is parsed flexibly - both label form and header form are accepted:
#   kali ip: 192.168.23.128        |   # IP
#   tailnet ip: 100.x.y.z          |   192.168.23.128
#   username: kali                 |   # Username
#   password: secret               |   kali
# Add a "tailnet ip:" line to make it reach the VM from off-LAN machines (needs Tailscale
# on this host + the VM on the same tailnet).
#
# Gotchas (see docs/virtual-machine.md): no stdin forwarding (base64 files INTO the command);
# no persistent state (chain with ; / &&); fails fast on unreachable (ConnectTimeout).
set -euo pipefail

CREDS="${VM_CREDS:-/root/creds.txt}"
[ -r "$CREDS" ] || { echo "vm.sh: cannot read $CREDS" >&2; exit 2; }

# _field "label1|label2" "HeaderName" -> first matching value, label form then header form.
_field() {
  local labels="$1" header="$2" v=""
  v=$(grep -ioE "^[[:space:]]*(${labels})[[:space:]]*[:=][[:space:]]*[^[:space:]#]+" "$CREDS" 2>/dev/null \
        | head -1 | sed -E 's/^[^:=]*[:=][[:space:]]*//')
  if [ -z "$v" ] && [ -n "$header" ]; then
    v=$(awk -v h="$header" 'BEGIN{IGNORECASE=1}
          $0 ~ "^[[:space:]]*#[[:space:]]*"h"[[:space:]]*$" {want=1; next}
          want && $0 !~ /^[[:space:]]*#/ && $0 !~ /^[[:space:]]*$/ {gsub(/^[[:space:]]+|[[:space:]]+$/,"");print;exit}' "$CREDS")
  fi
  printf '%s' "$v"
}

VMUSER=$(_field "username|user" "Username")
VMPASS=$(_field "password|pass" "Password")
TSIP=$(_field "tailnet[[:space:]]*ip|tailscale[[:space:]]*ip|ts[[:space:]]*ip" "")
LANIP=$(_field "kali[[:space:]]*ip|vm[[:space:]]*ip|ip" "IP")

[ -n "$VMUSER" ] || { echo "vm.sh: no username in $CREDS" >&2; exit 2; }
[ -n "$VMPASS" ] || { echo "vm.sh: no password in $CREDS" >&2; exit 2; }

CMD="${1:-}"
[ -n "$CMD" ] || { echo "usage: bash /root/vm.sh '<remote bash command>'" >&2; exit 2; }

# Candidate hosts, priority order, de-duplicated, empties skipped.
CANDS=()
for h in "$TSIP" "$LANIP"; do
  [ -n "$h" ] || continue
  dup=0; for e in "${CANDS[@]:-}"; do [ "$e" = "$h" ] && dup=1; done
  [ "$dup" = 0 ] && CANDS+=("$h")
done
[ "${#CANDS[@]}" -gt 0 ] || { echo "vm.sh: no VM IP in $CREDS (need 'kali ip:' and/or 'tailnet ip:')" >&2; exit 2; }

pick=""
for h in "${CANDS[@]}"; do
  if timeout 8 bash -c "exec 3<>/dev/tcp/$h/22" 2>/dev/null; then pick="$h"; break; fi
done
[ -n "$pick" ] || {
  echo "vm.sh: no VM reachable on :22 among [${CANDS[*]}]." >&2
  echo "       This host has no network path to the VM. Fixes: join the VM's Tailscale tailnet" >&2
  echo "       (install tailscale here + add its 100.x IP as 'tailnet ip:' in $CREDS), or run" >&2
  echo "       from the machine that hosts the VM LAN." >&2
  exit 4
}

exec sshpass -p "$VMPASS" ssh \
  -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
  -o ControlMaster=auto -o ControlPath="${TMPDIR:-/tmp}/vm-%r@%h:%p" -o ControlPersist=300 \
  "$VMUSER@$pick" "$CMD"
