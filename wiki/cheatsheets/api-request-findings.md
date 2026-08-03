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
| L5-Swagger (Laravel) | `/docs?api-docs.json`, `/api/documentation`, `/docs/asset/*` | GET | - | none by default | full OpenAPI spec of an otherwise undocumented API: operation list, path params, and which ops are writes (`PATCH /clients/{id}`, `DELETE /delete-invoice`). Publishing the spec alone is INFO, but it hands you the whole BOLA/BFLA test matrix |
| any calendar / schedule widget | the widget's own AJAX source (`events`, `availability`, `occupancy`, `busy-slots`) | GET | replay the exact params the page sends, then remove the scope flag | usually none | booking/appointment endpoints routinely serialise the whole `booking -> contract -> user` graph (name, e-mail, phone, payment state) while the page draws initials. Prime spot for unauthenticated mass PII |
| Joomla 4.0.0-4.2.7 | `/api/index.php/v1/config/application?public=true` | GET | needs `Accept: */*` (else 406 Not Acceptable) | none - CVE-2023-23752 | DB host/user/password + dbprefix; `/api/index.php/v1/users?public=true` leaks Super-User names/emails |

| Supabase / PostgREST | `/rest/v1/<bogus_table>` | GET | `apikey:<anon>` + `Authorization: Bearer <anon>` | anon key | **table-name enumeration even when the schema root is locked.** Modern Supabase returns 401 "Only the `service_role` API key can be used" on `/rest/v1/`, but a NONEXISTENT table returns `PGRST205` with `"hint":"Perhaps you meant the table 'public.<real_table>'"` -> fuzzy-match leaks real names. Seed with generic guesses, then follow each hint |
| Supabase / PostgREST | `/rest/v1/<table>?select=*` | GET | headers `Range: 0-0` + `Prefer: count=exact` | anon key | **proves table scale WITHOUT retrieving rows** (`Content-Range: 0-0/<total>`). The correct shape for enumeration limits: `*/0` = anon has SELECT but RLS returns nothing (RLS working); `0-0/<n>` with a row = RLS absent on that table -> data exposure. Judge the columns before calling it a finding: public reference data (venues, categories) is usually deliberately public |
| Supabase | `/auth/v1/settings` | GET | `apikey:<anon>` | anon key | read-only auth config: `disable_signup`, `mailer_autoconfirm`, enabled providers. Check BEFORE attempting signup-based privesc; `disable_signup:true` closes that path outright. NOTE `user_metadata` is user-writable by design, so injecting `role` at signup always "works" -- it is only a finding if the app authorizes off `user_metadata` instead of `app_metadata` or an RLS'd table |
| Next.js (App Router) | any path | GET | read the `x-matched-path` response header | none | **route-existence oracle**: real routes echo their own path, unrouted ones return `/_not-found`. Maps protected routes and unlinked pages without a wordlist. A middleware auth gate shows as a 3xx with NO `x-matched-path` |
| Next.js server actions | any page URL | POST | `Next-Action: <id>` + `Content-Type: text/plain;charset=UTF-8`, body = JSON array of args | none | server actions are publicly invocable endpoints. Recover IDs **with their function names** from the client chunks via `createServerReference("<id>", ..., "<fnName>")`. The ID keeps its leading `40` Flight prefix; stripping it returns "Server action not found". A foreign `Origin` header returning 500 means built-in server-action CSRF protection is active |
## How to extend
When a request pattern yields a finding on an engagement, add the **generic** form here (product, endpoint shape, payload, impact). Strip client host/path specifics. Cross-link the relevant technique page (e.g. [[supabase-attacks]], [[graphql]]).

<!-- promoted-slug: joomla-cve-2023-23752 -->
