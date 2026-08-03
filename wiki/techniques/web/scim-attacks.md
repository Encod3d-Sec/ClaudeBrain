---
title: "SCIM Provisioning Attacks"
type: technique
tags: [authentication, scim, identity, idor, provisioning, web]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [rfc7644-scim, scim-security-notes]
---

# SCIM Provisioning Attacks

## What it is
SCIM (System for Cross-domain Identity Management, RFC 7643/7644) is the REST protocol IdPs use to provision and de-provision users and groups into SaaS apps (create/update/delete users, set group membership). SCIM attacks abuse weakly protected SCIM endpoints to create or elevate accounts, read user data across tenants, or impersonate users, often bypassing the app's normal auth UI.

## How it works
A SaaS app exposes `/scim/v2/Users` and `/scim/v2/Groups` (and `/Me`), authenticated by a long-lived bearer token shared with the IdP. The endpoints are powerful (full user lifecycle) but are frequently under-tested compared to the main app. Common flaws: a leaked or guessable SCIM bearer token grants tenant-wide user control; a token not scoped to one tenant allows cross-tenant IDOR over user ids; PATCH operations that can set privileged attributes (admin role, group membership, externalId mapping) enable privilege grant; user creation without invitation enables account injection.

## Attack phases
Exploitation, privilege escalation, and persistence (provisioning a backdoor admin).

## Prerequisites
- App exposes SCIM provisioning endpoints.
- A SCIM bearer token (leaked in CI, repos, IdP config) or an endpoint with weak auth.
- For IDOR: a token not strictly scoped to one tenant/org.

## Methodology
1. Discover SCIM endpoints (`/scim/v2/Users`, `/Groups`, `/Me`, `/ServiceProviderConfig`).
2. Test the bearer token's scope: can it list or read users of other tenants (IDOR over `id`)?
3. Create a user (POST /Users) with attacker-controlled credentials/externalId; check whether it can log in.
4. PATCH a user to grant privileged group membership or an admin role attribute.
5. Map `externalId` to hijack the IdP-to-app identity link (account takeover at next SSO).
6. Enumerate via filters; test SCIM filter injection.

## Key payloads / examples
Provision a backdoor user:
```http
POST /scim/v2/Users HTTP/1.1
Authorization: Bearer <scim-token>
Content-Type: application/scim+json

{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
 "userName":"backdoor@evil.tld","active":true,
 "externalId":"victim-idp-id","emails":[{"value":"backdoor@evil.tld","primary":true}]}
```
Escalate via PATCH (add to admins / set role):
```http
PATCH /scim/v2/Users/<id> HTTP/1.1
Authorization: Bearer <scim-token>
Content-Type: application/scim+json

{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
 "Operations":[{"op":"replace","path":"roles","value":[{"value":"admin"}]}]}
```
IDOR and filter probes:
```
GET /scim/v2/Users/<other-tenant-user-id>
GET /scim/v2/Users?filter=userName eq "admin" or "1" eq "1"
```

## Bypasses and variants
- externalId remapping to take over the SSO identity binding at next login.
- Cross-tenant IDOR when the bearer token is not tenant-scoped.
- De-provision abuse (DoS): delete or deactivate legitimate users.

## Detection and defence
- Scope SCIM tokens to a single tenant; rotate them and store as secrets; never commit them.
- Authorize every SCIM operation against the token's tenant; reject cross-tenant ids.
- Restrict which attributes SCIM may set; never allow role/admin attributes via unfiltered PATCH.
- Log and alert on SCIM user creation and privilege changes.

## Tools
Burp or curl against the SCIM REST surface. See [[oauth-attacks]], [[saml-attacks]], [[identity-fabric]], and [[access-control]] for related identity and IDOR testing.

## Sources
- IETF RFC 7644 (SCIM Protocol) (slug: rfc7644-scim).
- SCIM provisioning security testing notes (slug: scim-security-notes).
