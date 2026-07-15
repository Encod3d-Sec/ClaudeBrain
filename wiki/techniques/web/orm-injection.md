---
title: "ORM Injection (ORM Leak)"
type: technique
tags: [orm-injection, injection, idor, data-exfiltration, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# ORM Injection (ORM Leak)

When a handler passes an attacker-controlled object straight into an ORM filter/where clause
(`Model.objects.filter(**request.data)`, `prisma.model.findMany(req.body.filter)`,
`Post.ransack(params[:q])`), the attacker controls the query DSL, not just a value. This is a
data-exfiltration and boolean-oracle primitive (not SQLi): traverse relations to reach columns
never meant to be exposed (password hashes, reset tokens, TFA secrets), and brute-force them one
char at a time via `startsWith`/`contains`/`regex` operators. Distinct from SQLi and NoSQLi:
the sink is the ORM's own filter grammar.

## Vulnerable shapes to grep for
- Django: `filter(**request.data)`, `.filter(is_secret=False, **request.data)`.
- Prisma (Node): `findMany(req.body.filter)`, `where: req.query.filter`.
- Beego (Go): `qs.Filter(userKey, userVal)`; Ransack (Ruby): `Model.ransack(params[:q])`.
- Entity Framework/OData: reflection `TextFilter` helpers, `$filter` on `IQueryable<T>`.

## Attack model
All engines follow `field__operator` / nested-object traversal:
1. Relational traversal: `created_by__user__password__startswith` reaches a foreign column.
2. Many-to-many loop-back bypasses row-level filters (`is_secret=False`, `published=true`) by
   joining from a permitted row back to a protected one, then leaking the protected field.
3. Oracle: response differs (row present/absent), row count, pagination `total`, or timing.
   When response is constant, force a DB error via `__regex` ReDoS to build a timing oracle.
4. Type-confusion / operator smuggling on auth flows: an equality check on a secret
   (`where: {resetToken: req.body.resetToken}`) becomes a predicate that matches without knowing
   the secret when the attacker submits an operator object (`{"resetToken":{"not":"E"}}`).

## Real-world
Harbor `q` filter (Beego) leaked hashes/salts/TOTP; Strapi Content API smuggled a
`where` tree via ignored top-level keys (CVE-2026-27886, unauth admin `resetPasswordToken` leak
then admin ATO); Directus CVE-2025-64748 (`TextFilter` leaked `token`+`tfa_secret`).

## Safe differential confirm
Strapi-style: baseline vs always-false predicate
(`?where[id][$lt]=-1`); on a vulnerable target `meta.pagination.total` changes, patched strips it.
Tune brute-force to the DB collation (many default collations are case-insensitive; use
regex/GLOB/BINARY when the secret's casing matters).

Payload strings: [[orm-injection]] (payloads). Related: [[rsql-injection]], [[nosql]], [[sqli]].

## Sources
- HackTricks (pentesting-web)
