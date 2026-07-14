---
title: "macOS SIP"
type: technique
tags: [macos, sip, privesc, evasion]
phase: privilege-escalation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## SIP bypass

System Integrity Protection blocks even root from modifying `/System`, `/bin`, `/sbin`, `/usr` (exceptions marked in `/System/Library/Sandbox/rootless.conf`) plus anything carrying the `com.apple.rootless` xattr, and restricts kext loading, task-ports for Apple procs, NVRAM writes, and kernel debugging. Config is a bitflag in NVRAM. Bypasses usually chain an entitlement that grants SIP exception (see [[macos-code-signing]]), most often `com.apple.rootless.install.heritable`, whose child processes of `system_installd` inherit the bypass.

Check status and protection flags:

```bash
csrutil status                       # SIP enabled?
csrutil authenticated-root status    # sealed system volume seal
ls -lOd /usr/libexec                 # "restricted" flag = SIP-protected
ls -lOd /usr/libexec/cups            # "sunlnk" = cannot delete
```

Known bypass classes: Apple-signed installer packages bypass SIP; creating a listed-but-missing file (e.g. a plist in `/System/Library/LaunchDaemons`) persists; and the heritable-install chain has produced repeated CVEs:
- CVE-2019-8561: swap the pkg after signature check.
- CVE-2021-30892 (Shrootless): `system_installd` invokes zsh post-install, which sources a malicious `/etc/zshenv` as the SIP-exempt process. Note `~/.zshenv` also fires on `sudo -s`.
- CVE-2022-22583: mount a virtual image over `/tmp` to swap the post-install script.
- CVE-2023-42860: symlink `${SHARED_SUPPORT_PATH}/SharedSupport.dmg` so the InstallAssistant postinstall unrestricts arbitrary files.

Mount-over-a-protected-folder primitive:

```bash
mkdir evil
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Sandbox/ evil.dmg
```

Relevant SIP entitlements to hunt on binaries: `com.apple.rootless.install[.heritable]`, `com.apple.rootless.kext-management`, `com.apple.rootless.restricted-nvram-variables[.heritable]`, `com.apple.rootless.datavault.controller`.
