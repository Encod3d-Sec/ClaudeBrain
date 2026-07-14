---
title: "Payloads: Session Attacks"
type: payloads
tags: [payloads, session, cookies, authentication, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: Session Attacks

Session fixation, prediction, and cookie weaknesses (OWASP A07). Routed via the `hunt-auth` skill. See [[session-management-attacks]]; tokens [[jwt-attacks]].

## Cookie flag / scope checks
```
missing Secure -> sent over http (MITM)        missing HttpOnly -> XSS steals it
SameSite=None without Secure / no SameSite -> CSRF
Domain=.target.com -> any subdomain (XSS on sub) reads it
overly long expiry / no rotation on login (fixation)
```

## Session fixation
```
1. attacker gets a valid pre-auth session id (or sets one: ?sessionid=ATTACKER or via XSS/meta)
2. victim logs in -> server keeps the SAME id (no rotation)
3. attacker reuses the id -> authenticated as victim
test: does the session id change after login? (it MUST)
```

## Predictable / weak session id
```
sequential / timestamp / userid-derived ids
short or low-entropy tokens -> collect many, model the PRNG (Mersenne Twister -> randcrack)
base64-decode the cookie: leaks username/role/uid -> tamper
unsigned/Base64 "JWT-like" or serialized session -> edit role (see deserialization)
```

## Logout / lifecycle
```
session not invalidated on logout / password change / reset -> old cookie still works
concurrent sessions allowed (no kill-others on password change)
"remember me" token weak/forgeable/not bound to device
session puzzling: a value set in one flow trusted in another (e.g. reset flow sets uid)
```

## Token-in-cookie (JWT/opaque)
```
JWT in cookie: alg:none / weak HS256 / kid (see jwt)
opaque token: try IDOR (swap), reuse another user's, replay after logout
```

## Real-world
Missing session rotation on login (fixation), no invalidation on password change, and low-entropy/base64-decodable cookies are recurring auth findings; combine with XSS (no HttpOnly) for theft.
