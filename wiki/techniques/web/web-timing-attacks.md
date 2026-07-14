---
title: "Web Timing Attacks"
type: technique
tags: [side-channel, race-condition, recon, ssrf, server-side, web, portswigger]
phase: exploitation
date_created: 2026-06-18
date_updated: 2026-06-18
sources: [kettle-listen-to-the-whispers]
---

# Web Timing Attacks

## What it is

Web timing attacks infer server-side secrets from response-time differences, with no need for the response content to change or for an out-of-band callback. Historically unreliable over the internet because of network jitter, they became practical with the **single-packet attack**: place two HTTP/2 requests in one TCP packet so they arrive simultaneously, then read the order responses come back in. This is jitter-independent ("timeless"), turning a remote timing attack into something closer to a local one. Basis: James Kettle, "Listen to the whispers: web timing attacks that actually work" (PortSwigger Research, Black Hat USA 2024), validated across ~30,000 live sites.

## Why it works now

- **Single-packet / dual-packet sync.** Coalesce HTTP/2 header frames into the final packets so both requests are decrypted and queued before processing. Disable `TCP_NODELAY`, withhold the last frame, then release with a ping frame. Reduces the differential needed from ~30,000us down to ~200us.
- **Response-order, not absolute time.** You compare which of a paired requests responds first across many samples (report at ~80% bias), instead of measuring milliseconds against a noisy clock.
- **Same primitive as race conditions.** The single-packet attack is the same one used in [[race-conditions]]; Burp's built-in race/timing tooling and Turbo Intruder both expose it.

## Measurement methodology

- Take ~30 samples per probe; compare the **bottom quartile** (least-noisy subset) of each side. Report only when the quartiles do not overlap.
- **Maximise signal:** force slow code paths (ORM, GraphQL, ReDoS), multiply work with repeated fixed-prefix headers, inject randomness to defeat server caching.
- **Minimise noise:** use cache hits / object reuse as a fast baseline, target shortest paths, optionally shed concurrent load.

## Techniques

### Hidden parameter and route discovery

Param Miner augmented with a response-time attribute finds parameters that change processing time even when the response body does not.

```
commonconfig: x   -> 55ms
commonconfig: {}  -> 50ms   (5ms delta => valid JSON-parsed parameter)
```

Cache-key discovery via cached-vs-uncached timing:

```
GET /?id=random   -> 310ms  (cache miss => 'id' is keyed)
GET /?foo=random  -> 22ms   (cache hit  => 'foo' unkeyed)
```

### Scoped SSRF detection via timing

When a proxy only forwards to internal subdomains, classic OAST/pingback fails. Prove a back-end DNS lookup happens purely by timing (see [[ssrf]], [[dns-rebinding]]):

```
Host: abc.example.com  -> 25ms  (first lookup)
Host: abc.example.com  -> 20ms  (cached => lookup happened)
```

For non-caching resolvers, abuse the 63-octet DNS label limit:

```
Host: aaa...a{62}.example.com -> 25ms  (lookup performed)
Host: aaa...a{63}.example.com -> 20ms  (label rejected, no lookup)
```

Param Miner ships "Detect scoped SSRF" / "Exploit scoped SSRF" scans that then enumerate alternate routes and guess useful forwarded headers.

### Front-end impersonation

Front-ends inject trusted headers (`X-Forwarded-For`, custom auth) the back-end trusts blindly. Use scoped-SSRF routing to reach the back-end directly and spoof them. Real case: New Relic `Service-Gateway-Is-Newrelic-Admin` header reached via request tunnelling to hit an internal admin API. See [[http-host-header-attacks]], [[reverse-proxy-attacks]].

### Blind injection detection

When sleep payloads are filtered, timing still reveals processing differences:

- **SQLi:** `?mic='` (162ms) vs `?mic=''` (170ms) - order bias distinguishes valid vs broken syntax. See [[sql-injection]].
- **JSON injection:** invalid escape `key=a\"bb` vs `key=a"\bb` - a ~200us delta from downstream error logging; the delta vanishing when input is redacted points at a logging sink.
- **Server-side parameter pollution:** reserved chars (`%23` `#`) vs non-reserved (`%21` `!`) shift processing time, exposing back-end parsing. Most prolific finding type in the research. See [[hpp-attacks]].

## Tooling

- **Param Miner** - response-time attribute; scoped-SSRF detect/exploit; subdomain enumeration (cert transparency, Project Sonar fdns).
- **Turbo Intruder** - custom timing attacks, response-order analysis (~80% bias threshold, ~30s windows).
- **Burp Suite** - single-packet attack built into race-condition discovery; timing available in scanner and manual tools.

## Defense

- Per-IP rate limit (e.g. 1 req / 1-5ms); detect multi-request single packets and split with microsecond delays.
- Constant-time comparison for secret/key verification.
- Avoid making security-relevant work observably faster/slower than the default path.

## Sources

- James Kettle, PortSwigger Research, "Listen to the whispers: web timing attacks that actually work" (Black Hat USA 2024) (slug: kettle-listen-to-the-whispers) (`https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work`).
