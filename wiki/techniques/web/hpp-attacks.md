---
title: "HTTP Parameter Pollution"
type: technique
tags: [exploitation, hpp, injection, waf-bypass, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-hpp]
---

# HTTP Parameter Pollution (HPP)

## What it is

Supplying the same parameter name multiple times (`?p=a&p=b`). There is no HTTP spec for parsing duplicates, so different stacks pick first/last/all - and a WAF, app, and backend may disagree. Attackers abuse that disagreement to bypass WAFs/validation, override values, or alter logic. Pairs with [[business-logic]]; cache-relevant for [[web-cache-poisoning]].

## How it works
Two levels: **server-side** (how the framework reads duplicates) and **client-side** (input reflected into a URL/form that the browser then re-parses). The exploit is the **parser differential**: the security control reads one value, the sink reads the other.

### Parsing by stack (`?par=a&par=b`)
| Technology | Result |
|------------|--------|
| ASP.NET / IIS | `a,b` (all) |
| PHP / Apache | `b` (last) |
| Node.js / Express | `a,b` (all -> array) |
| JSP / Tomcat, Flask, Go `Get()` | `a` (first) |
| Django, Rails | `b` (last) |

## Methodology / exploitation
```text
param=value1&param=value2          # duplicate
param[]=v1&param[]=v2              # array
param=value1%26other=value2        # encoded & to smuggle a second param
param[key1]=v1&param[key2]=v2      # nested
{"test":"user","test":"admin"}     # JSON duplicate key (last-wins in many parsers)
```
Use cases:
- **WAF bypass:** put the benign value where the WAF looks, the payload where the app reads (e.g. SQLi/XSS split across `id=1&id=' OR 1=1`).
- **Value override / privilege:** `role=user&role=admin`, `amount=100&amount=1`, `email=victim&email=attacker` (reset poisoning).
- **Auth/OTP logic:** duplicate `otp`/`email` to confuse verification.
- **Cache / param cloaking:** unkeyed duplicate alters the cached response.

## Real-world
Used to bypass WAF signature matching and to flip business-logic values (price, role, recipient) where the validation layer and the executing layer parse duplicates differently. A staple of payment/reset bug-bounty chains.

## Detection and defence
Decide a single canonical parameter source and reject duplicates (or explicitly take first and validate); keep the WAF, app, and backend on the **same** parsing rule; validate type + count server-side; for JSON, reject duplicate keys.

## Tools
Burp Repeater (manual duplicate/array), OWASP ZAP, `Param Miner`. See [[business-logic]], [[sql-injection]] (WAF-bypass chains).

## Sources
- PayloadsAllTheThings - HTTP Parameter Pollution
