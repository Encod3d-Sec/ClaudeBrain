---
name: hunt-api
description: API attack hunting (REST / GraphQL / gRPC) - BOLA/IDOR, BFLA, mass assignment, excessive data exposure, auth/JWT, introspection + batching, rate-limit abuse. OWASP API Top 10. Wiki-first, FIND schema output.
---

# Hunt: API Security

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "api security BOLA mass assignment" via wiki-search MCP -> read matching page.
```
Core pages: [[api-security]], [[api-testing]]. Overlaps [[access-control]] (BOLA -> hunt-idor), [[jwt-attacks]], [[graphql]] payloads. Payload arsenal: `wiki/payloads/api.md`.

**Self-heal:** wiki query empty -> create stub `wiki/techniques/web/api-security.md` before proceeding.

## Scope Check
- Confirm in scope. Get the spec if any (Swagger/OpenAPI, GraphQL introspection, `.proto`). Read `Deadends.md`.

## Attack Surface Signals
`/api/`, `/v1/`, `/graphql`, `/rest/`, gRPC (`application/grpc`, HTTP/2), Swagger UI (`/swagger`, `/api-docs`, `/openapi.json`), mobile/SPA backends.

## Methodology
1. **Enumerate:** parse Swagger/OpenAPI for every endpoint + param; GraphQL introspection (`__schema`); gRPC server reflection (`grpcurl -plaintext <h> list`). No spec? discover endpoints with `ffuf -w <api-wordlist> -u https://HOST/FUZZ` and probe/fingerprint hosts with `httpx`, not a hand curl loop. Keep a single manual `curl` per account only for the BOLA/IDOR PoC in the writeup.
2. **BOLA / IDOR (API #1):** swap object IDs across accounts (numeric, UUID, in body/path/header) - the dominant API bug. -> overlaps `hunt-idor`.
3. **Broken function-level auth (BFLA):** call admin/privileged methods as a low-priv user; swap HTTP verb (GET->PUT/DELETE); hit undocumented endpoints from the spec.
4. **Mass assignment:** add fields the client never sends (`role`, `isAdmin`, `verified`, `balance`) to JSON bodies; observe privilege/state change.
5. **Excessive data exposure:** the API returns more than the UI shows (full objects, other users' fields) - inspect raw responses.
6. **Auth:** JWT flaws ([[jwt-attacks]]: alg:none, weak secret, kid), API-key reuse, missing auth on some routes, OAuth scope.
7. **GraphQL specifics:** introspection, batching/aliases (brute/rate-limit bypass), nested-query DoS, field suggestion. Payloads: [[graphql]].
8. **gRPC specifics:** reflection to enumerate; `grpcurl` to call methods; tamper protobuf fields; same authz tests as REST.
9. **Rate limit / resource:** unbounded pagination, no throttle on sensitive actions (OTP/login -> brute).
10. **Distill to wiki (when confirmed):** if a request pattern generalizes (product +
    endpoint + impact), stage a GENERIC wiki candidate now:
    `python3 scripts/wiki-stage.py --kind api-pattern --slug <product>-<endpoint>`.
    Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed:
```
Create Vulns/Research/FIND-XXX-<SEV>-api-<issue>-<host>.md   (e.g. FIND-021-HIGH-bola-orders-api.md)
Add row to Vuln-index.md: | FIND-XXX | BOLA on /api/orders/{id} | host | CONFIRMED |
```
Severity: CRITICAL = unauth admin action / cross-tenant data; HIGH = BOLA/BFLA to other users' data, mass-assign privesc; MEDIUM = excessive exposure, rate-limit gaps.

Exhausted (object IDs authorised server-side, function auth enforced, extra fields ignored, JWT sound):
```
Append to Deadends.md: - [ ] API <host> -- BOLA/BFLA/mass-assign all enforced; JWT validated; introspection off
```

Report: Status + files created.
