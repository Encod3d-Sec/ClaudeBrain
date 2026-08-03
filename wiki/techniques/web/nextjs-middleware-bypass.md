---
title: "Next.js Middleware Authorization Bypass (CVE-2025-29927)"
type: technique
tags: [web, nextjs, authorization-bypass, cve, access-control]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-07-02
sources: [jfrog-cve-2025-29927, projectdiscovery-cve-2025-29927, zhero-nextjs-cache-chains]
---

# Next.js Middleware Authorization Bypass (CVE-2025-29927)

## What it is
CVE-2025-29927 (CVSS 9.1, March 2025) is an authorization bypass in Next.js. Middleware (commonly used for auth, redirects, and route protection) can be skipped entirely by sending a crafted `x-middleware-subrequest` request header, because Next.js blindly trusts that internal header to short-circuit middleware.

## How it works
Next.js uses the `x-middleware-subrequest` header internally to prevent infinite middleware recursion: when the framework makes an internal subrequest, it sets this header so middleware is not re-run. The flaw is that the value is trusted from the incoming request without verifying it originated internally. An attacker who sets the header to the expected value makes Next.js treat the request as an internal subrequest and skip middleware execution, so any access control, authentication redirect, or path protection implemented in middleware is bypassed. Any route protected only by middleware becomes directly reachable.

## Attack phases
Exploitation; authorization bypass and access control.

## Prerequisites
- Target runs a vulnerable Next.js version (before 12.3.5, 13.5.9, 14.2.25, or 15.2.3).
- Authorization is enforced in middleware (the common pattern).

## Methodology
1. Fingerprint Next.js (`x-powered-by: Next.js`, `/_next/` assets, build manifest version).
2. Identify a route protected by middleware (login redirect, admin area).
3. Resend the request with the `x-middleware-subrequest` header set to the expected sentinel; middleware is skipped and the protected route responds.
4. The exact value depends on version: it encodes the middleware module path (`middleware` or `src/middleware`), and newer branches expect a repeated chain of it.

## Key payloads / examples
Bypass header (value varies by version family):
```http
GET /admin HTTP/1.1
Host: target
x-middleware-subrequest: middleware
```
Newer branches expect a repeated/chained value matching the middleware module path:
```http
x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware
```
A successful bypass returns the protected content that would otherwise redirect to login.

## Bypasses and variants
- Can also enable cache poisoning and DoS in some setups.
- The required value differs across the 12.x / 13.x / 14.x / 15.x branches; enumerate `middleware` vs `src/middleware` and the chain depth.

## Detection and defence
- Upgrade to Next.js 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 or later.
- Where patching is blocked: at the load balancer or reverse proxy, strip or block any external request carrying `x-middleware-subrequest`.
- Defence in depth: do not rely solely on middleware for authorization; enforce authz in the route handler and data layer.

## Detection symptom
When middleware rewrites/blocks everything, **every path returns the same page** (`/`, `/admin`,
even `/_next/static/*.js` and `_buildManifest.js` all serve the identical HTML). That uniformity is
the tell that a middleware is intercepting all requests - the routes behind it become reachable once
the header is set.

## Delivering the header through an SSRF (gopher)
If the Next.js app is internal-only and you reach it via an SSRF that only takes a URL
(`?url=` / preview / fetch), you **cannot set `x-middleware-subrequest` with a plain fetch** - a
`?url=` GET sends fixed headers. Tunnel a raw HTTP request carrying the header over **gopher**:
```python
# raw request with the bypass header, sent via gopher through the SSRF sink:
req=b'GET /customapi HTTP/1.1\r\nHost: 127.0.0.1:10000\r\nx-middleware-subrequest: middleware\r\nConnection: close\r\n\r\n'
# gopher://127.0.0.1:10000/_<percent-encoded req>  ->  ?url=<that, re-encoded>
```
Full `gopher()` + `send(method,path,headers,...)` builder in [[wiki/techniques/web/ssrf]] payloads. This was the exact
unlock on THM Extract (internal Next.js on :10000 behind an SSRF); run it via the hunt-ssrf skill.

## Internal cache poisoning chains (CVE-2024-46982)

A separate Next.js bug class from the middleware bypass above: internal cache poisoning by tricking the framework into caching a dynamic (SSR) response as if it were static (SSG). Basis: Rachid Allam (zhero), "Next.js, cache, and chains: the stale elixir" (2025 top-10 #7), CVE-2024-46982.

**Mechanism (source-level chain).** In `server/base-server.ts`, an `isSSG` check decides whether a response is cacheable, and it trusts the inbound `x-now-route-matches` header. An SSR route normally ships `Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate`; misclassified as SSG it instead gets `s-maxage=1, stale-while-revalidate`, which a shared CDN/cache will store. The attacker chains three inputs against a non-dynamic SSR route:

- `?__nextDataReq=1` forces data-fetch (JSON) mode,
- `x-now-route-matches: 1` forces the SSG classification,
- a reflected value (`User-Agent`, cookie, CSRF token) becomes the cached payload.

```http
GET /dashboard?__nextDataReq=1 HTTP/1.1
Host: target
x-now-route-matches: 1
User-Agent: <img src=x onerror=alert(document.domain)>
```

The reflected `User-Agent` from `getServerSideProps` is cached as `text/html` and served to every subsequent visitor.

**Impact:** stored XSS (reflected payload cached for all users); DoS (poisoned JSON served where HTML is expected breaks the page globally); cache deception (another user's dynamic response cached against a shared key).

**Affected / scope:** Next.js 13.5.1 through 14.2.9, Pages router, non-dynamic SSR routes (`pages/dashboard.tsx`, not `pages/blog/[slug].tsx`), self-hosted only (Vercel unaffected). Fix: upgrade to 14.2.10 or later; strip `x-now-route-matches` from external requests at the proxy; never derive cacheability from a client-supplied header.

## Tools
curl or Burp to add the header on a directly-reachable target; gopher-over-SSRF (above) when the app
is only reachable internally. See [[access-control]] and [[authentication-attacks]].

## Sources
- JFrog, "CVE-2025-29927 - Authorization Bypass Vulnerability in Next.js" (slug: jfrog-cve-2025-29927).
- ProjectDiscovery, "CVE-2025-29927: Next.js Middleware Authorization Bypass - Technical Analysis" (slug: projectdiscovery-cve-2025-29927).
- Rachid Allam (zhero), "Next.js, cache, and chains: the stale elixir" (CVE-2024-46982, 2025 top-10 #7) (slug: zhero-nextjs-cache-chains) (`https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir`).
