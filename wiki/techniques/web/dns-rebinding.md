---
title: "DNS Rebinding"
type: technique
tags: [bypass, dns, network, ssrf, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-dnsrebinding]
---

# DNS Rebinding

## What it is

DNS rebinding repoints an attacker-controlled domain from a public IP to an **internal** IP after the victim's browser has loaded attacker JavaScript - so the browser, still treating the page as the same origin, makes and **reads** requests to internal services (`127.0.0.1`, `192.168.x.x`, IoT/router admin, internal APIs). It turns any victim browser into an SSRF proxy into the LAN, bypassing the Same-Origin Policy. Related: [[ssrf]].

## How it works

### The attack flow
1. **Setup:** register `malicious.com` with a custom authoritative DNS server you control.
2. **Initial resolution:** victim visits `malicious.com` -> resolves to your **public** IP, browser loads your JS.
3. **Rebind:** your DNS server uses a very short TTL; the next request re-resolves the domain and you now answer with the **internal** target IP.
4. **Exploit:** the browser treats the internal IP as the same origin -> your JS reads responses from internal services and exfiltrates them.

Modern browsers cache DNS (pinning), so reliable rebinding uses a faster trick (below) rather than waiting on TTL.

## Methodology / variants
- **Multiple A records (fastest):** answer with BOTH your public IP and the target's internal IP. The browser connects to one; when you firewall-drop your public IP, the browser retries the internal one on the same origin - rebinds in seconds (Singularity's "multiple A record" strategy).
- **TTL=0** classic rebind for clients that honor it.
- Probe the internal service first (timing/error oracle) to confirm it is up before rebinding.

## Targets (high value)
Unauthenticated services bound to localhost/LAN that trust the network: router/IoT admin panels, blockchain node RPC (Geth/Parity historically), media servers (Plex/Transmission had rebinding CVEs), internal dashboards/metrics, Docker API `:2375`, and dev servers. Cloud metadata (`169.254.169.254`) usually needs a header so is partial.

## Protection bypasses (defeating IP allow/deny filters)
### 0.0.0.0
Targets `localhost` on Linux/macOS, bypassing filters that only block `127.0.0.0/8`.
### CNAME / localhost CNAME
Return a CNAME the filter does not resolve before deciding:
```text
cname.example.com.      381   IN   CNAME   target.local.
localhost.example.com.  381   IN   CNAME   localhost.
```
### IP encodings
Decimal/hex/octal forms of internal IPs (`2130706433`, `0x7f000001`) to dodge string filters - same set as [[ssrf]].

## Tools
```bash
# Singularity of Origin - full rebinding framework (server + payloads + manager UI)
git clone https://github.com/nccgroup/singularity; # run the DNS+HTTP server, point malicious domain's NS at it
# rbndr - simple public rebinding service: <hex-ip1>.<hex-ip2>.rbndr.us alternates between the two
host 7f000001.c0a80001.rbndr.us
```
- [nccgroup/singularity](https://github.com/nccgroup/singularity) - rebinding framework with prebuilt service payloads.
- [taviso/rbndr](https://github.com/taviso/rbndr) - quick two-IP rebinding service.

## Detection and defence
**Validate the `Host` header** against an allowlist (the core fix - reject unexpected hostnames), require authentication on localhost/LAN services, DNS pinning / `dns-rebind-protection` on resolvers (block RFC1918 answers from external domains), and CORS/origin checks. Browsers mitigate but cannot fully prevent it.

## Sources
- PayloadsAllTheThings - DNS Rebinding
