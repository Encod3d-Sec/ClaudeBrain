---
title: "macOS Launch Constraints and Trust Cache"
type: technique
tags: [macos, evasion, mitigations, post-exploitation]
phase: post-exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Launch/environment constraints and trust cache

Launch Constraints (Ventura+) regulate how, by whom, and from where a binary may start, defeating many classic macOS attacks. Each Apple binary is assigned a Launch-Constraint category (facts + boolean logic) recorded in the trust cache, enforced by AMFI (see [[macos-amfi]]). Four constraint types: Self (the binary), Parent (its parent process), Responsible (the process driving it over XPC), and Library-load. On `execve`/`posix_spawn` the OS checks self + parent + responsible constraints; failure means the program does not run. On Apple Silicon, an Apple-signed binary absent from the trust cache is refused by AMFI outright.

What this kills: launching a system binary from an unexpected location, invocation by an unexpected parent (many daemons must be launched only by `launchd`), and downgrade attacks (old signed binaries no longer runnable). What it does NOT stop: common XPC abuses (see [[macos-xpc-abuse]]), Electron code injection, and dylib injection without library validation. Enumerate a third-party app's Environment Constraints, and dump/parse the trust caches to find binaries with constraint category 0 (unconstrained):

```bash
codesign -d -vvvv /Applications/App.app        # shows Environment Constraints

python3 -m pip install pyimg4
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/tc.im4p
pyimg4 im4p extract -i /tmp/tc.im4p -o /tmp/tc.data
pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/policy.data

# trustcache tool: 4th column per entry = constraintCategory (0 = unconstrained)
trustcache info /tmp/policy.data | head
```

Trust cache entry layout: `{ uint8 cdhash[20]; uint8 hash_type; uint8 flags; uint8 constraintCategory; uint8 reserved; }`. LC categories are defined in the AMFI kext as DER/ASN.1 blobs (symbols `kConstraintCategory*`); decode with a KDK + an ASN.1 decoder. Attacker takeaway: prefer unconstrained binaries (category 0) as injection or proxy-exec targets, since constrained ones refuse abnormal parents/paths.
