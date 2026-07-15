---
title: "macOS Enumeration Cheatsheet"
type: cheatsheet
tags: [macos, enumeration, post-exploitation, cheatsheet]
phase: post-exploitation
sources: [hacktricks-macos]
---

# macOS Enumeration Cheatsheet

Fast local enumeration for a macOS foothold. For credential and DB harvesting after this pass, see [[macos-loot-locations]].

## Automated tools

MacPEAS (linpeas), SwiftBelt, Metasploit `enum_osx`.

## Manual system / service / network map

```bash
# system + users + services
system_profiler SPSoftwareDataType SPApplicationsDataType SPStartupItemDataType SPFirewallDataType
sw_vers; uname -a; id; who; launchctl list; atq; sysctl -a | head
diskutil list

# content search (Spotlight-backed, fast)
mdfind "kMDItemFSName == '*.pem'"; mdfind password
mdfind "kMDItemContentType == 'com.apple.property-list'" | head

# network + shares + listeners
networksetup -listallnetworkservices
networksetup -getwebproxy Wi-Fi; networksetup -getautoproxyurl Wi-Fi   # proxy config
lsof -i -P -n | grep LISTEN
arp -i en0 -l -a; smbutil statshares -a
scutil --dns | grep nameserver

# app entitlements / signing of an interesting binary
codesign -dvvv --entitlements :- /Applications/App.app 2>&1 | head -40
```

## Notes worth grabbing

- `pbpaste` (clipboard)
- `screencapture -x /tmp/s.jpg` (triggers a TCC prompt)
- `caffeinate &` (keep awake during a long task)

Privileged toggle seen on engagements: `sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist` (enable Remote Login).

## Anti-analysis awareness

Malware commonly checks for VM/hypervisor via `system_profiler SPHardwareDataType`, `sysctl -n machdep.cpu.brand_string`, and MAC-address OUI, so blue-team detections and red-team evasion both key off these.

## Sources

- HackTricks (macos-hardening).
