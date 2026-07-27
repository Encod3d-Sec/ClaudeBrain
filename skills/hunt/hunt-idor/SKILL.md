---
name: hunt-idor
description: >
  IDOR / BOLA hunting - two-account methodology, identifier discovery and UUID leak chaining,
  the trusted-identifier test, GraphQL node and nested-object IDOR, cross-tenant escalation,
  write and delete operations. Bounded ID sampling, never range sweeps. Wiki-first, FIND schema
  output. Trigger on IDOR, BOLA, broken access control, object level authorization, cross-tenant,
  "read another user's data", "swap the id", or any API path or parameter carrying a numeric ID,
  UUID, or account identifier.
---

# Hunt: IDOR / Broken Object Level Authorization

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration
limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "IDOR BOLA insecure direct object reference access control" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[access-control]]. Payload arsenal: `wiki/payloads/idor.md`.
Anchors: [[uuid-insecurities]] (v1-UUID timestamp/MAC when an object ID is a UUID rather than a
sequential integer), [[jwt-attacks]] (chain a trusted `sub`/`user_id` claim to ATO, hand off to hunt-auth).

## Attack surface signals

URL patterns: `/api/v1/users/{id}`, `/invoices?id=`, `/reports/{uuid}/`, `/messages/{thread_id}`,
`/admin/orgs/{org_id}/members`

GraphQL: any query or mutation taking an `id` argument. Check for `node(id: "...")` global
lookups - one endpoint reaching every object type, with per-type authorization frequently missing
on at least one.

**Rank before testing.** Not all endpoints are equally likely:

- **Newest features** - middleware follows codebase conventions; a feature written outside them
  misses it.
- **Bulk and export endpoints** - one request, many objects, much higher severity per finding.
- **Anything carrying two identifiers** - see the trusted-identifier test below.
- **Cross-service internal calls** - the internal hop often carries no user context at all.
- **File and document access** - frequently a separate host or CDN with no authorization beyond
  knowing the ID.
- **Non-GET verbs on read-looking endpoints** - `GET /orders/123` authorized, `PATCH` not.

## Where the identifiers are

Check all of these; the least obvious are the least protected. Path segments, query parameters,
request bodies (including nested objects), headers (`X-User-Id`, `X-Account-Id`, `X-Tenant-Id`),
cookies, JWT claims, GraphQL variables, WebSocket messages, and file/CDN URLs.

**Get B's identifiers from B.** Log in as B and read them from B's own traffic, profile page, or
JWT. Record in `identities.md`. Never obtain an identifier by incrementing until you find out
whose it is - that is enumerating real users.

**Decode opaque identifiers before assuming they are random.** Base64 and hex frequently decode
to a plain integer or a `type:id` pair. Where the ID is a hash, test whether it hashes something
knowable (email, user ID, timestamp) and compute B's offline.

## UUID: a two-part finding

A random UUID is not an authorization control, but it is a practical barrier. The finding becomes
a chain:

1. **The check is missing** - test with B's UUID, which you legitimately hold.
2. **The UUID is obtainable** - find where it leaks.

Report both together. Part 1 alone gets triaged down as "requires an unguessable identifier."

Leak sources worth working: search and autocomplete endpoints, notification and activity feeds,
team and member lists, verbose errors, notification emails, exported files, share and invite
links, and objects you *can* read that reference objects you cannot.

Also verify the UUID is actually random - v1 encodes timestamp and MAC ([[uuid-insecurities]]),
and hand-rolled implementations frequently emit sequential values dressed as UUIDs.

## Methodology

**Setup:** two accounts per `hunt-core`. A owns, B attacks. Separate profiles.

**Drive it through Burp** for operator visibility. With A's request captured in Repeater or proxy
history:

```
scripts/burp/idor-sweep.py <eng> <reqfile> --attacker-auth "Cookie: session=USER_B" --range 5
```

Sends owner-baseline / idor-test / bounded id sample through `send_http1_request`, diffs status
and body, prints a verdict and a ready `capture.sh burp` PoC line. Honors `no_bruteforce` ->
range 0. **Do not raise `--range` above the `hunt-core` limits without operator approval.**

For GUI-visible replay: `create_repeater_tab` for an A tab and a B tab, or `send_to_intruder`
with a bounded number payload.

1. **Log in as A, browse every feature, note every ID** - object, UUID, org, invoice, thread.
2. **Baseline both directions.** A requests A's object. B requests B's object. Record status,
   length, body shape. You are testing against these, not against intuition.
3. **Cross-request:** B requests A's object with B's session.

```bash
# Baseline - A owns it
curl -s -H "Cookie: session=USER_A" https://target.com/api/v1/invoices/12345

# Cross-account - B attempts
curl -s -H "Cookie: session=USER_B" https://target.com/api/v1/invoices/12345
```

4. **Rule out legitimate access before claiming anything.** Is the object shared with B, in a
   shared team, public, or org-visible? Check the UI as B. This is the single most common false
   positive in this class - an app with sharing features generates them constantly.
5. **Trusted-identifier test - run this on every endpoint carrying two identifiers.** The highest
   value test in IDOR and the most frequently skipped. Make the session and the parameter
   disagree:

```
Session: account B
Body:    {"user_id": "<A's id>", "action": "..."}
```

- Server acts on B -> identity derived from session, parameter ignored. Correct.
- Server acts on A -> **the parameter is trusted.** IDOR, usually critical, fully
  attacker-controlled.
- Server errors on mismatch -> it compares them. Correct, and evasion is the next step.

Apply the same to JWT claims: modify `sub` / `user_id` and see whether the server derives the
acting user from the claim or looks it up. Trusted claim plus weak signature chains to arbitrary
account takeover - hand off to `hunt-auth`.

6. **All verbs.** GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS. Authorization applied per-method
   rather than per-resource is common.
7. **When the direct swap 403s, it is not closed.** Parameter pollution (`?id=A&id=B` - the check
   and the fetch may read different occurrences), array wrapping (`{"id":["A","B"]}`), nested
   wrapping (`{"user":{"id":"B"}}`), path traversal in the identifier, encoding and case variation,
   **version downgrade** (`/v1/` predates the middleware `/v2/` has - the most reliable of these),
   and batch endpoints where per-item authorization is missing.
8. **Cross-tenant.** Two accounts in *different* orgs. Categorically more severe than
   user-to-user inside one tenant: it breaks the isolation the product is sold on and implicates
   every customer. Say "cross-tenant" in the title - it changes who reads the report.
9. **GraphQL.** Nested traversal is the signature bug - the entry point is authorized, the
   resolvers are not:

```graphql
query { me { organization { members { id email phone } } } }
```

Walk every edge from an authorized root. Also test `node(id:)` global lookups, aliases for
parallel object access in one request, and mutations that introspection reveals but the UI never
calls.

10. **Write and delete.** More severe, more dangerous. Test on your own objects first to learn the
    request shape. **Prefer reversible operations** - changing B's display name proves it;
    deleting B's account proves the same and destroys your setup. Confirm from B's side.
    **Never test a destructive write against an identifier you have not confirmed is B's.**
11. **Bounded ID sampling - never a range sweep.** Per `hunt-core`: five identifiers by default,
    twenty ceiling with approval, zero under `no_bruteforce`. Two or three adjacent IDs establish
    a sequential pattern; that is the whole proof. For scale, cite the `total` or pagination
    count, not retrieved records.

```bash
# Bounded sample around a known ID - NOT a range sweep
known=48291
for i in $(seq $((known-2)) $((known+2))); do
  printf '%s ' "$i"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
    -H "Authorization: Bearer USER_B_TOKEN" \
    "https://target.com/api/v1/orders/$i"
done
```

12. **Automate the breadth, verify every flag by hand.** Session-replay tooling (Autorize-style)
    replaying every request under B's session while you browse as A turns this into a background
    pass. It produces false positives on endpoints returning identical public content - it narrows
    the queue, it does not produce findings.
13. **Distill when confirmed** - reusable GraphQL IDOR or UUID-bypass technique, GENERIC, no
    client host: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/access-control.md`

## Confirmation gate

**NOT confirmation:** a `200` with an empty or shell response; the object echoed back from your
own request; B seeing an object that is shared, public, or org-visible; a response you have not
compared against A's baseline; a write returning `200` with no state change verified from B's
side.

**IS confirmation:** B's session returns A's *data*, matching A's own baseline response, with A's
legitimate-access ruled out, reproduced in a clean session - and for writes, the change visible
in B's UI.

## Severity

Rated on the object, not the mechanism.

| Object | Typical |
|---|---|
| Session token, API key, reset token | critical - direct ATO |
| Full user records with PII | critical / high |
| Payment or billing detail | critical / high |
| Private documents, messages | high |
| Account settings (write) | high - enables takeover via email change |
| Internal identifiers only | low - enables other attacks |

**Write outranks read** at the same object. **Unauthenticated outranks authenticated** by a full
band. **Cross-tenant outranks cross-user.** An unguessable identifier you cannot show leaking
lowers it - chase the leak first.

## Deadends

```
Append: - [ ] IDOR on <host> <endpoint> -- 403/404 cross-account, authorization enforced;
              tried pollution/array/verb/version downgrade
```

Record what you tried, not just that it failed. The next pass needs to know the boundary.
