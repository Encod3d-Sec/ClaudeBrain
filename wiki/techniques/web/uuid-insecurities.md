---
title: "UUID Insecurities (v1 Sandwich Attack)"
type: technique
tags: [uuid, account-takeover, idor, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# UUID Insecurities (v1 Sandwich Attack)

UUID version is fixed at the 13th hex digit (the M in `xxxxxxxx-xxxx-Mxxx-Nxxx-...`). Only v4 is
random; v1 is time+clock-seq+MAC based and therefore predictable across UUIDs generated close in
time. Any security-sensitive UUID that is v1 (password-reset link, invite token, object id used for
access control) is guessable.

## Sandwich attack (password reset)
The attacker triggers a reset for attacker-account-1, then
immediately for the victim, then for attacker-account-2, capturing UUID-1 and UUID-2 by email.
Because time-based UUIDs are monotonic, the victim's UUID falls between them; enumerate the range
and replay `/reset/<uuid>` until it works. Requires weak/no rate-limiting on the reset endpoint.

## Recon
Any UUID with `1` in the version nibble is a candidate; a leaked MAC/node from one v1 UUID
also narrows the space. Tools: Lupin-Holmes/sandwich (automates the range attack), Burp
UUID Detector extension.

Related: [[account-takeover]], [[access-control]].

## Sources
- HackTricks (pentesting-web)
