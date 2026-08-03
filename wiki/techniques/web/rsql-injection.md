---
title: "RSQL / FIQL Injection"
type: technique
tags: [rsql, fiql, injection, idor, api, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# RSQL / FIQL Injection

RSQL (superset of FIQL) is a URI-friendly filter language for REST APIs
(`/products?filter=price>100;category==electronics`). Common on Spring/JPA and JSON:API/Elide
backends. When filters are not sanitized against an allow-list of selectors, an attacker gains an
IDOR/authz-bypass/enumeration primitive by traversing relations and choosing operators, similar to
ORM Leak but over an explicit URL query grammar.

## Fingerprint
Send `?filter=id==test`, `?q==test`, or a malformed operator `=foo=`; verbose parsers
leak "Unknown operator"/"Unknown property". Non-standard operators (`=like=`, `=ilike=`, `=all=`,
`=isnull=`, `=between=`) reveal Elide/custom JPA translators (larger attack surface). Pull
`/swagger`/OpenAPI to recover valid selectors without brute force.

## Exploitation
- Enumeration/leak: `filter[userAccounts]=email=='victim@x.com'` returns the full user object
  instead of a boolean; wildcards `id=in=(*a*)` dump entire tables past a 403.
- Authz evasion + privesc: filter by an admin's id (`filter[companyUsers]=user.id=='<adminId>'`)
  to enumerate admins, then reuse that id in a permissions endpoint to inherit admin functionality.
- IDOR via `include`: `?include=language,country&filter[users]=id=='<victimId>'` returns another
  user's profile; `include` can pull extra attributes (password, tokens).
- Relationship traversal via dotted paths (`author.books.price.total`); test the same predicate on
  root and related collections (authz bugs often exist on only one path).
- CVE-2022-24827 (Elide analytics): a `TEXT` field-argument containing `--` stripped the generated
  authorization `WHERE` clause. On analytics endpoints test whether operands reach SQL before auth.

Bypass naive blocklists/WAF by double-encoding `( ) * ; ` (e.g. `%2528admin%2529`); many
implementations double-parse URL params.

Payload strings: [[rsql]] (payloads). Related: [[orm-injection]], [[access-control]].

## Sources
- HackTricks (pentesting-web)
