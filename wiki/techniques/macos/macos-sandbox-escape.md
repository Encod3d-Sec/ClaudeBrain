---
title: "macOS Sandbox Escape"
type: technique
tags: [macos, sandbox, privesc, evasion]
phase: privilege-escalation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## App Sandbox escape

An app with the `com.apple.security.app-sandbox` entitlement runs inside the App Sandbox, enforced by MACF hooks (`Sandbox.kext`, `sandboxd`) using SBPL profiles. On macOS a process opts in (unlike iOS), and App Store apps are always sandboxed. Each sandboxed app gets a container at `~/Library/Containers/{BundleID}/Data`. Escapes come from loose entitlement exceptions (see [[macos-code-signing]]), suspending the sandbox, abusing an XPC/mach service outside the container, or writing files the sandbox forgot to constrain.

Run a binary under an arbitrary profile to test what a profile allows:

```bash
sandbox-exec -f example.sb /path/to/binary
sandbox-exec -n no-internet ping 8.8.8.8
sbtool <pid> all                 # inspect a live proc's profile, file and mach access
sbtool <pid> file /tmp           # file-access check for a path
```

Trace every sandbox check a process makes, then read the profile that was denied:

```bash
cat > /tmp/trace.sb <<'EOF'
(version 1)
(trace /tmp/trace.out)
EOF
sandbox-exec -f /tmp/trace.sb /bin/ls
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
```

Inspect a container config (needs FDA, not just root):

```bash
plutil -convert xml1 ~/Library/Containers/<BundleID>/.com.apple.containermanagerd.metadata.plist -o -
```

Escape classes to look for: entitlement `com.apple.security.temporary-exception.sbpl` (your SBPL string is eval'd as a profile), `sandbox_suspend` when the proc holds `com.apple.private.security.sandbox-manager` or `com.apple.security.print`, sandbox extension tokens (long hex, not PID-bound, consumable by other procs), and the classic Office bypass of writing files whose name starts with `~$` outside the container. Loosening entitlements like `com.apple.security.network.server` auto-grant matching extensions.
