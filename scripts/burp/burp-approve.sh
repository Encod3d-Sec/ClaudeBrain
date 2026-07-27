#!/usr/bin/env bash
# burp-approve.sh -- FALLBACK: auto-click "Always Allow Host" on a pending Burp MCP approval popup.
#
# PRIMARY is scripts/burp/burp-scope-sync.py: it puts the engagement's in-scope hosts into Burp's scope
# so in-scope MCP sends AUTO-APPROVE with no popup. Run that per engagement. This script is the safety
# NET for when you forgot to scope-sync an in-scope host and a send is now stuck behind the approval
# dialog: it clicks "Always Allow Host" so the host is approved (sticky) and the send proceeds.
#
# It VERIFIES the dialog is present (the orange "Allow Once" button pixel) before clicking, so it never
# clicks blindly into the Repeater editor. COORDINATE-BASED and thus BRITTLE: the MCP approval dialog is
# a Swing overlay (not an addressable X window), positioned at a fixed offset from the Burp frame centre
# on this Kali seat (measured for Burp 2026.3.x at ~1348x1085). If Burp is resized/re-laid-out the offsets
# below may need re-measuring. Synthetic mouse only registers on an UNLOCKED seat (see setup/burp/disable-lock.sh).
#
#   bash scripts/burp/burp-approve.sh          # approve a pending popup (no-op if none is up)
# Env: VM_SH (SSH bridge, default /root/vm.sh).
set -uo pipefail
VM_SH="${VM_SH:-/root/vm.sh}"

read -r -d '' VMSCRIPT <<'PYEOF' || true
U=$(who | awk '/\(:[0-9]/{print $1; exit}'); U=${U:-kali}
D=$(who | grep -oE '\(:[0-9]+' | head -1 | tr -d '('); D=${D:-:0}
run(){ sudo -u "$U" env DISPLAY="$D" XAUTHORITY="/home/$U/.Xauthority" "$@"; }
WID=$(run xdotool search --name "Burp Suite Professional" | head -1)
[ -n "$WID" ] || { echo "burp-approve: no Burp window on $D"; exit 1; }
G=$(run xdotool getwindowgeometry "$WID")
X=$(echo "$G" | awk -F'[ ,]+' '/Position/{print $3}')
Y=$(echo "$G" | awk -F'[ ,]+' '/Position/{print $4}')
W=$(echo "$G" | awk '/Geometry/{split($2,a,"x"); print a[1]}')
H=$(echo "$G" | awk '/Geometry/{split($2,a,"x"); print a[2]}')
CX=$((X + W/2)); CY=$((Y + H/2))
AO_X=$((CX + 135)); AO_Y=$((CY + 105))    # orange "Allow Once" -> dialog-present probe
AA_X=$((CX + 313)); AA_Y=$((CY + 105))    # "Always Allow Host" -> sticky approve
HEX=$(run import -window root -crop 1x1+${AO_X}+${AO_Y} -depth 8 txt:- 2>/dev/null | grep -oE '#[0-9A-Fa-f]{6}' | head -1)
R=0; G8=0; B=0
if [ -n "$HEX" ]; then R=$((16#${HEX:1:2})); G8=$((16#${HEX:3:2})); B=$((16#${HEX:5:2})); fi
# Burp accent orange is ~#E8722C (R high, G mid, B low). Lenient band avoids a false negative.
if [ "$R" -gt 170 ] && [ "$G8" -ge 70 ] && [ "$G8" -le 175 ] && [ "$B" -lt 95 ]; then
  run xdotool windowactivate --sync "$WID"; sleep 0.3
  run xdotool mousemove "$AA_X" "$AA_Y" click 1; sleep 0.4
  echo "burp-approve: clicked 'Always Allow Host' at $AA_X,$AA_Y (probe $HEX)"
else
  echo "burp-approve: no approval dialog detected (probe $HEX at $AO_X,$AO_Y not orange). Nothing to approve; prefer burp-scope-sync."
  exit 2
fi
PYEOF
B64=$(printf '%s' "$VMSCRIPT" | base64 -w0)
bash "$VM_SH" "echo '$B64' | base64 -d > /tmp/burp_approve_vm.sh; bash /tmp/burp_approve_vm.sh; rm -f /tmp/burp_approve_vm.sh"
