---
name: hunt-macos
description: macOS attack hunting - foothold to root/persistence on a macOS host. TCC/Gatekeeper/SIP bypass, keychain + credential loot, code-signing/entitlements abuse, XPC/dylib/library injection, launch-constraint evasion, MDM/installer abuse. Wiki-first, FIND schema output.
---

# Hunt: macOS

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "macOS TCC SIP Gatekeeper AMFI keychain XPC dylib injection sandbox escape code signing entitlements" via wiki-search MCP
```

Hub: [[macos-moc]] (live index). Primary page: [[macos-tcc]]. Payload arsenal: `wiki/payloads/macos-app-injection.md`.
Anchors: [[macos-privesc]] (general privesc checklist), [[macos-keychain]] (credential/DB harvest).

## Environment note

macOS boxes on THM/HTB are usually a VM (not real Apple hardware) - SIP/Gatekeeper/TCC still apply as
shipped, but device-specific protections (Secure Enclave, T2) generally do not. Confirm root/admin vs a
sandboxed app context before picking an escalation path - the sandbox-escape and TCC-bypass techniques
below assume different starting points.

## Attack surface signals

Detected via: SSH/service banner (`Darwin`, `Mac OS X 10.`, `macOS 1[1-5]`), a `.app` bundle / `.plist`
delivered as a foothold vector, Bonjour/mDNS (5353), ARD/screen-sharing (5900/3283), SMB served by
`smbd` with a macOS-flavoured share layout, or a CTF prompt naming macOS/Darwin explicitly.
Footholds: a delivered `.pkg`/`.dmg`/`.app` (installer/Gatekeeper abuse), a web app or service running
as a low-priv user, physical/VNC/screen-sharing access to a logged-in session.

**Rank the surface** once you have a foothold:

- **TCC / SIP / Gatekeeper / AMFI** - the macOS-specific security stack; a bypass here is the signature
  finding of this class and the primary path to protected data or unsigned code exec.
- **Keychain / credential loot** - highest reward-per-effort; a login-keychain dump or a reused hash
  often beats grinding a hardened control (see chaining note).
- **XPC / dylib / library injection** - inherit a privileged or entitled process's rights; the main
  local-privesc lever once enumeration finds a vulnerable service or a hijackable load path.
- **Sandbox escape** - only relevant from a sandboxed app context; escapes to the full user context.
- **MDM / installer abuse** - a `.pkg` postinstall runs as root at install time; MDM enrollment reaches
  the whole fleet. Highest blast radius when either is present.

## Methodology

1. **Enumerate the foothold first** - `Skill(arsenal)` then [[macos-enumeration]]: users, running
   processes/services (launchd agents/daemons), installed `.app` bundles, network map, SIP status
   (`csrutil status`), Gatekeeper status (`spctl --status`), TCC database location + entries.
```bash
csrutil status                          # SIP enabled/disabled - gates which privesc paths are live
spctl --status                          # Gatekeeper assessment on/off
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "select * from access"   # per-app TCC grants
```
2. **Credential / secret loot** - [[macos-keychain]] (login keychain dump, `security` CLI, keychain
   ACL bypass) then the wider sweep in [[macos-loot-locations]] (local password hashes under
   `/var/db/dslocal/`, browser/app credential stores, sensitive DBs) - crack recovered hashes with
   hashcat `-m 7100` (salted SHA512-PBKDF2).
3. **Evasion / bypass the OS security stack** (pick per what's actually gating you):
   - [[macos-gatekeeper]] - quarantine-attribute stripping, unsigned/ad-hoc-signed app execution.
   - [[macos-code-signing]] - signature/entitlement inspection and abuse (`codesign`, ad-hoc re-signing).
   - [[macos-amfi]] - AppleMobileFileIntegrity internals underlying code-signing enforcement, and its bypasses.
   - [[macos-launch-constraints]] - trust-cache / launch-constraint evasion on newer macOS.
   - [[macos-dirty-nib]] - NIB-file injection into a signed app to gain its entitlements.
4. **Privilege escalation / sandbox escape** - [[macos-privesc]] (the general checklist: SUID, sudo,
   cron/launchd, writable app bundles) alongside:
   - [[macos-sandbox-escape]] - escape an app sandbox profile to the full user context.
   - [[macos-xpc-abuse]] - abuse a privileged XPC service's exposed Mach interface.
   - [[macos-function-hooking]] / [[macos-library-injection]] / [[macos-thread-injection]] /
     [[macos-app-injection]] (payload) - `DYLD_INSERT_LIBRARIES`/dylib hijack/thread-injection into a
     privileged or entitled process to inherit its rights.
   - [[macos-authorization-db]] - Authorization Services rights-database manipulation for a privesc.
   - [[macos-tcc]] - TCC bypass to reach protected data (contacts/photos/full-disk-access/camera) or
     ride a TCC-granted app's entitlement.
   - [[macos-installers-abuse]] - `.pkg` postinstall-script / `.dmg` abuse for root-run code at install time.
   - [[macos-chromium-injection]] - inject into a Chromium-based app (Electron/Chrome) via its debug/CEF
     surface for code exec in that app's context.
5. **Persistence + lateral** - [[macos-persistence]] (launch agents/daemons, login items, cron) and
   [[macos-mdm]] (enrolled-MDM abuse for fleet-wide reach, if the host is MDM-managed).

**Chaining.** Foothold -> keychain/credential loot -> privesc is the reliable macOS chain: a
low-priv shell first dumps the login keychain and `/var/db/dslocal/` hashes ([[macos-keychain]] /
[[macos-loot-locations]]), a cracked or reused admin password then unlocks sudo/`security` and the
privileged XPC/dylib paths in step 4. Loot before you grind a hardened control.

**Evasion.** Prefer the least-noisy path that clears the gate: strip the `com.apple.quarantine`
xattr rather than fully re-sign, ride an already-TCC-granted app's entitlement rather than defeating
TCC head-on, and load via a hijackable dylib search path before touching AMFI/launch-constraint
internals. Escalate to heavier bypasses ([[macos-amfi]], [[macos-launch-constraints]]) only when the
lighter path is actually blocked.

Distill a confirmed reusable macOS technique per hunt-core: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/macos/macos-privesc.md`.

## Confirmation gate

**NOT confirmation:** a permissive entitlement (`com.apple.security.*`, a `get-task-allow` or a
private-framework entitlement) present in a plist; an unsigned or ad-hoc-signed binary sitting on
disk; a world-writable app bundle or launchd plist; `csrutil`/`spctl` reporting a control as present;
a `DYLD_INSERT_LIBRARIES` that the loader ignored on a hardened process. A capability that *exists*
is not a control that was *bypassed*.

**IS confirmation:** the control was actually defeated and demonstrated - TCC bypassed and the
protected resource (contacts/photos/full-disk/camera) actually read; SIP-protected path written or
`csrutil`-guarded action performed; Gatekeeper/AMFI/launch-constraint bypassed and your unsigned code
*ran* past it; an injected dylib/thread executing inside the privileged/entitled process and
exercising its rights; a `.pkg` postinstall or XPC call yielding a root-context action you performed -
each re-verified in a clean session and reproduced from your own written steps.

## Severity

| Severity | Class |
|---|---|
| CRITICAL | root / SIP-disabled code exec, MDM fleet compromise |
| HIGH | sandbox escape, XPC privesc, keychain-wide credential dump |
| MEDIUM | TCC bypass to a single data class, Gatekeeper bypass with no privilege gain |
