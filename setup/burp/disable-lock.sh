#!/usr/bin/env bash
# disable-lock.sh -- permanently stop the Kali seat from locking/blanking, so GUI automation
# (burpshot / xdotool driving Burp) never has its synthetic input routed to a locker.
#
# WHY: a Kali screen LOCK (xfce4-screensaver) on seat0 routes synthetic keys/clicks to the locker,
# so `getmouselocation` over an app reports window:0 and NOTHING lands -- `capture.sh burp` then fails
# its precheck (it now loginctl-unlocks first, but a box that never locks is the durable fix).
#
# Runs ON the Kali box as root (uses `sudo -u <seatuser>` for the X/session bits). Idempotent.
#   On the box:      sudo bash setup/burp/disable-lock.sh
#   From the vault:  base64 -w0 setup/burp/disable-lock.sh | \
#                      xargs -I{} bash /root/vm.sh 'echo {} | base64 -d > /tmp/disable-lock.sh; bash /tmp/disable-lock.sh'
set -u
U=$(who | awk '/\(:[0-9]/{print $1; exit}'); U=${U:-kali}
D=$(who | grep -oE '\(:[0-9]+' | head -1 | tr -d '('); D=${D:-:0}
UID_=$(id -u "$U"); BUS="unix:path=/run/user/$UID_/bus"
run() { sudo -u "$U" env DISPLAY="$D" XAUTHORITY="/home/$U/.Xauthority" DBUS_SESSION_BUS_ADDRESS="$BUS" "$@"; }

# 1) xfce4-screensaver: disable the saver + every lock-activation path (create the key if absent)
for kv in /saver/enabled /lock/enabled /lock/saver-activation/enabled \
          /lock/session-sleep-activation/enabled /lock/suspend-activation/enabled; do
  run xfconf-query -c xfce4-screensaver -p "$kv" -s false 2>/dev/null \
    || run xfconf-query -c xfce4-screensaver -p "$kv" --create -t bool -s false 2>/dev/null || true
done

# 2) stop it autostarting on future logins (user Hidden override of the system .desktop)
mkdir -p "/home/$U/.config/autostart"
printf '%s\n' '[Desktop Entry]' 'Type=Application' \
  'Name=xfce4-screensaver (disabled: GUI automation needs a live seat)' \
  'Exec=/bin/true' 'Hidden=true' 'X-XFCE-Autostart-enabled=false' \
  > "/home/$U/.config/autostart/xfce4-screensaver.desktop"

# 3) kill DPMS/blank on every login (autostart .desktop + ~/.xprofile) and now
printf '%s\n' '[Desktop Entry]' 'Type=Application' 'Name=Disable screen blank/DPMS (burp GUI automation)' \
  'Exec=sh -c "xset s off; xset s noblank; xset -dpms"' \
  'X-XFCE-Autostart-enabled=true' 'X-GNOME-Autostart-enabled=true' \
  > "/home/$U/.config/autostart/zz-no-screenblank.desktop"
XP="/home/$U/.xprofile"; touch "$XP"
grep -q 'burp: no screen blank' "$XP" 2>/dev/null || \
  printf '\n%s\n%s\n%s\n%s\n' '# burp: no screen blank / no DPMS / no lock (GUI automation needs a live seat)' \
    'xset s off' 'xset s noblank' 'xset -dpms' >> "$XP"
chown -R "$U:$U" "/home/$U/.config/autostart" "$XP"

# 4) apply to the CURRENT session + stop any running saver
run xset s off; run xset s noblank; run xset -dpms
pkill -u "$U" -f xfce4-screensaver 2>/dev/null || true

# verify
echo "saver_enabled=$(run xfconf-query -c xfce4-screensaver -p /saver/enabled 2>/dev/null)"
echo "lock_enabled=$(run xfconf-query -c xfce4-screensaver -p /lock/enabled 2>/dev/null)"
run xset q | grep -iE 'timeout:|DPMS is'
echo "saver_running=$(pgrep -u "$U" -f xfce4-screensaver | wc -l)"
