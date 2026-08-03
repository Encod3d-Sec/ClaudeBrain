---
title: "Default Credentials"
type: cheatsheet
tags: [cheatsheet, credentials, default-creds]
sources: []
date_created: 2026-06-05
date_updated: 2026-06-05
---

# Default Credentials

Reusable list of product/appliance default credentials. **Check here before any credential work** when you identify a product; if you hit the same product on a later engagement, reuse from here instead of re-researching.

`source`: `vendor` (documented default, often via context7 product docs) or `observed` (seen in the field; record the generic product fact only, never the client host/IP).

Per the engagement discipline, default-cred checks are an acceptable early move; broad spraying of captured creds is a last resort. See [[bug-hunting-methodology]].

| product | version | username | password | source | notes |
|---------|---------|----------|----------|--------|-------|
| MSSQL | any | sa | (blank) / sa | vendor | SQL auth; check before assuming |
| Tomcat Manager | any | tomcat / admin | tomcat / admin / s3cret | vendor | /manager/html |
| Grafana | any | admin | admin | vendor | forces reset on first login |
| Jenkins | any | admin | admin / (install token) | vendor | initialAdminPassword file |
| PostgreSQL | any | postgres | postgres / (blank) | vendor | |
| Elasticsearch | <8 | (none) | (none) | vendor | unauth by default pre-8 |
| RabbitMQ | any | guest | guest | vendor | localhost-only by default |
| InfluxDB | 1.x | (none) | (none) | vendor | auth often disabled |

## How to extend
- New product encountered: look up vendor defaults via `context7` (resolve the library/product, query for default credentials), add a row with `source: vendor`.
- Default observed in the field: add a row `source: observed` with the **generic** product + cred only. Client-specific hostnames/IPs stay in `targets/<eng>/loot.md`.
