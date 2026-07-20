---
name: hunt-macos
description: macOS attack hunting - foothold to root/persistence on a macOS host. TCC/Gatekeeper/SIP bypass, keychain + credential loot, code-signing/entitlements abuse, XPC/dylib/library injection, launch-constraint evasion, MDM/installer abuse. Wiki-first, FIND schema output.
---

# Hunt: macOS

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "<technique: TCC bypass | SIP bypass | Gatekeeper bypass | XPC abuse | dylib injection | keychain dump | macOS persistence>" via wiki-search MCP -> read matching page.
```
Hub: [[macos-moc]] (links every macOS technique page). Core pages: [[macos-privesc]], [[macos-tcc]],
[[macos-sip]], [[macos-gatekeeper]], [[macos-sandbox-escape]], [[macos-keychain]], [[macos-xpc-abuse]],
[[macos-persistence]], [[macos-code-signing]]. Payload: [[macos-app-injection]]. Cheatsheets:
[[macos-enumeration]] (fast local recon), [[macos-loot-locations]] (credential/DB harvest map).

**Self-heal:** wiki query empty -> create stub `wiki/techniques/macos/<slug>.md` (frontmatter + `##
Observed during <engagement>`), link it from [[macos-moc]], before proceeding.

## Scope + Safety Gate (READ FIRST)
- Confirm the macOS host/user is in scope. Read `Deadends.md` + `loot.md` - reuse captured creds first.
- macOS boxes on THM/HTB are usually a VM (not real Apple hardware) - SIP/Gatekeeper/TCC still apply as
  shipped, but device-specific protections (Secure Enclave, T2) generally do not.
- Confirm root/admin vs a sandboxed app context before picking an escalation path - the sandbox-escape
  and TCC-bypass techniques below assume different starting points.

## Attack Surface Signals
Detected via: SSH/service banner (`Darwin`, `Mac OS X 10.`, `macOS 1[1-5]`), a `.app` bundle / `.plist`
delivered as a foothold vector, Bonjour/mDNS (5353), ARD/screen-sharing (5900/3283), SMB served by
`smbd` with a macOS-flavoured share layout, or a CTF prompt naming macOS/Darwin explicitly.
Footholds: a delivered `.pkg`/`.dmg`/`.app` (installer/Gatekeeper abuse), a web app or service running
as a low-priv user, physical/VNC/screen-sharing access to a logged-in session.

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

## FIND Output
Confirmed:
```
Create Vulns/Research/FIND-XXX-<SEV>-<issue>-<host>.md
Add row to Vuln-index.md: | FIND-XXX | TCC bypass -> full-disk access | <host> | CONFIRMED |
```
Severity: CRITICAL = root/SIP-disabled code exec, MDM fleet compromise; HIGH = sandbox escape, XPC
privesc, keychain-wide credential dump; MEDIUM = TCC bypass to a single data class, Gatekeeper bypass
with no privilege gain.

Exhausted (SIP enabled + no writable privileged launchd script + no vulnerable XPC service found):
```
Append to Deadends.md: - [ ] macOS privesc <host> -- SIP on, no writable root launchd/cron, no XPC found
```
