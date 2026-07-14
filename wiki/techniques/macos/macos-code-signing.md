---
title: "macOS Code Signing"
type: technique
tags: [macos, code-signing, evasion, post-exploitation]
phase: post-exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-macos]
---

## Code signing inspection and requirements

Every Mach-O carries an `LC_CODE_SIGNATURE` load command pointing at a SuperBlob (Code Directory, Requirements, Entitlements, CMS signature). The CDHash is a hash-of-hashes over each code page plus special slots (Info.plist, resources, entitlements). The kernel verifies the signature before execution, and AMFI re-verifies on each launch. For an attacker the interesting outputs are the signer identity, the entitlements, and the designated requirement (which csreq-keyed TCC grants pin to, see [[macos-tcc]]).

```bash
codesign -dv --entitlements :- /System/Applications/Automator.app  # dump entitlements
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"  # signer
codesign --verify --verbose /Applications/App.app                  # tamper check
codesign -d -r- /bin/ls                                            # designated requirement
codesign -d -vvvvvv /bin/ps                                        # CDHash + per-page slot hashes
codesign -s -  /tmp/toolsdemo                                      # ad-hoc sign
codesign -s "Developer ID Application: ..." /tmp/toolsdemo         # sign with a cert
```

Compile a signing requirement string to bytes (for TCC csreq blobs or allowlist rules):

```bash
csreq -b /tmp/output.csreq -r='identifier "com.example.app" and anchor apple generic and certificate leaf[subject.OU] = TEAMID123'
od -A x -t x1 /tmp/output.csreq
```

Attacker-relevant code-signing flags: `CS_ADHOC` (ad-hoc, no real identity), `CS_GET_TASK_ALLOW` (task port grabbable, injectable), `CS_REQUIRE_LV` (library validation on), `CS_RUNTIME` (hardened runtime), `CS_PLATFORM_BINARY` (platform binary; many protections trust these, so re-signing to gain platform status is an escalation angle).

## Dangerous entitlements enumeration

Entitlements grant capabilities the sandbox and TCC otherwise block. `com.apple.*` entitlements are Apple-only unless an enterprise cert lets you mint your own. Hunting binaries that carry a dangerous entitlement gives ready-made injection or privilege targets.

High-impact entitlements and what each grants:
- `com.apple.rootless.install[.heritable]`: bypass SIP (heritable is inherited by children, see [[macos-sip]]).
- `com.apple.system-task-ports` (old `task_for_pid-allow`): task port of any non-kernel process.
- `com.apple.security.get-task-allow`: this binary's task port is grabbable, enabling code injection.
- `com.apple.security.cs.debugger`: call `task_for_pid()` on third-party apps that have get-task-allow.
- `com.apple.security.cs.disable-library-validation`: load dylibs not signed by Apple or the same Team ID, enables dylib injection (see [[macos-library-injection]]).
- `com.apple.security.cs.allow-dyld-environment-variables`: use DYLD env vars to inject.
- `com.apple.private.tcc.manager` / `com.apple.rootless.storage.TCC`: modify the TCC database.
- `com.apple.private.icloud-account-access`: reach iCloudHelper XPC for iCloud tokens.
- `keychain-access-groups`: which keychain groups the app can read (see [[macos-keychain]]).
- TCC service entitlements: `kTCCServiceSystemPolicyAllFiles` (FDA), `kTCCServiceAppleEvents` (drive other apps), `kTCCServiceEndpointSecurityClient` (write user TCC DB), `kTCCServiceAccessibility` / `kTCCServicePostEvent` (synthesize input), `kTCCServiceListenEvent` (keylog via CGEventTap).

Enumerate binaries carrying a target entitlement (swap the grep string):

```bash
find /Applications -name "*.app" -exec sh -c '
  b="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
  [ -f "$b" ] && codesign -d --entitlements - "$b" 2>&1 | grep -q "disable-library-validation" && echo "$1"
' _ {} \; 2>/dev/null

systemextensionsctl list                 # system/driver extensions
find / -name "*.dext" -type d 2>/dev/null # DriverKit binaries (IOKit/kernel surface)
```
