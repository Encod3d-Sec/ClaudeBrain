---
title: "Parser Differentials (When Interpretation Becomes a Vulnerability)"
type: technique
tags: [methodology, parser-differential, request-smuggling, ssrf, access-control, cache-poisoning, meta]
phase: exploitation
date_created: 2026-07-02
date_updated: 2026-07-02
sources: [portswigger-top10-2025]
---

# Parser Differentials (When Interpretation Becomes a Vulnerability)

## What it is

A parser differential is a vulnerability that exists because **two components parse the same input differently**. One component (a security control: WAF, allowlist, auth check, router, cache key) reads the input one way and passes it; a second component (the sink: proxy, backend, fetch client, file system, template engine) reads the same bytes another way and does something dangerous with them. The bug is not in either parser alone; it lives in the gap between them.

This page is a meta-methodology that unifies a family of concrete bugs already documented across this wiki. Whenever you see a check and a sink on the same input, ask: do they agree on exactly what that input means?

## How it works

Every input string is parsed against a grammar (URL, HTTP framing, hostname, JSON, XML, content-type, filename, MIME). Real parsers diverge on edge cases: what a delimiter is, how duplicates are handled, how ambiguous or malformed input is normalised, how Unicode is folded. When the validator and the sink use different parsers (or the same parser configured differently, or different versions), an attacker crafts input that both parsers accept but interpret as two different values. The control validates its interpretation (benign); the sink acts on its interpretation (malicious).

Canonical differential axes:

- **URL parsing**: `scheme://user@host@evil/path`, backslash vs slash, `#`/`?` placement, `@`, `[]`, percent-encoding, embedded credentials. The check reads the authority as `host`, the fetcher reads it as `evil`. Drives [[ssrf]] and [[open-redirect]].
- **HTTP request framing**: `Content-Length` vs `Transfer-Encoding`, obsolete line folding, header duplication, HTTP/2-to-HTTP/1.1 downgrade. Front end and back end disagree on where one request ends and the next begins: [[http-request-smuggling]].
- **Hostname / Host header**: absolute-URI request line vs `Host` header, duplicate `Host`, port confusion, trailing dot, `X-Forwarded-Host`: [[http-host-header-attacks]].
- **Parameter parsing**: duplicate keys, array syntax, `;` vs `&` separators, encoding, where one layer takes the first value and another the last: [[hpp-attacks]].
- **Cache key vs served content**: the cache normalises/keys the request one way while the origin varies its response on an unkeyed input, so poisoned or wrong content is stored and served: [[web-cache-poisoning]], [[web-cache-deception]].
- **Content-type / MIME**: the validator trusts a declared type or extension while the interpreter sniffs or parses differently (polyglots, `application/json` vs `text/html`).
- **XML / JSON**: duplicate keys, comment handling, entity expansion, encoding declarations; the auth layer and the business layer read different values from the same document.
- **Unicode / encoding normalisation**: NFC/NFKC folding, case folding, overlong encodings collapse an attacker string into a forbidden one after the check ran; see also [[crlf-injection]].

The PortSwigger Top 10 Web Hacking Techniques of 2025 named "Parser Differentials: When Interpretation Becomes a Vulnerability" (joernchen) as a distinct class, and the same year's list included several members of the family: Unicode normalization exploitation, an SSRF technique via HTTP redirect loops, HTTP/2 CONNECT abuse, and a Next.js internal cache-poisoning chain.

## Attack phases

Primarily exploitation and access-control bypass. Also enumeration: probing how each layer parses is itself the discovery step. Applies wherever a request crosses a trust boundary between two parsers (proxy to app, gateway to service, WAF to backend, cache to origin, client to server).

## Prerequisites

- At least two components process the same input, and at least one is a security control (allowlist, auth, router, WAF, cache key).
- The two components use different parsers, different configs, or different versions.
- You can observe (directly or via side channels) how each side interpreted your input.

## Methodology

1. **Map the pipeline.** List every hop the input traverses (CDN, WAF, reverse proxy, load balancer, app, cache, fetch client, DB, template engine). See [[reverse-proxy-attacks]]. Each hop is a parser.
2. **Identify the check and the sink** on the same input. The differential only matters when a validator and a dangerous consumer read the same bytes.
3. **Enumerate the parsers.** Fingerprint each layer's stack (nginx, Envoy, HAProxy, Node/undici, Python urllib/requests, Go net/url, Java URL, browser). Parser behaviour is version and library specific.
4. **Craft ambiguous input** on the relevant axis (URL, framing, host, params, content-type, encoding) so the check accepts one meaning and the sink acts on another.
5. **Confirm the split.** Prove the two layers disagreed: an out-of-band callback for [[ssrf]], a timing or differential response for [[http-request-smuggling]], a cached poisoned response, an auth bypass reaching a forbidden route.
6. **Escalate** to the sink's native impact (SSRF to metadata, smuggling to request hijack, cache poisoning to stored XSS, access-control bypass to admin route).

## Key payloads and examples

URL authority confusion (validator sees allowed host, fetcher connects elsewhere):

```text
https://allowed.example.com@attacker.example/         # userinfo vs host
https://attacker.example\@allowed.example.com/         # backslash normalisation
https://allowed.example.com#@attacker.example/         # fragment vs authority
http://allowed.example.com%252f@attacker.example/      # double-encoded slash
```

CL.TE request smuggling (front end uses Content-Length, back end uses Transfer-Encoding):

```http
POST / HTTP/1.1
Host: victim.example
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Host / cache-key differential (origin varies on an unkeyed header the cache ignores):

```http
GET /home HTTP/1.1
Host: victim.example
X-Forwarded-Host: attacker.example
```

Parameter-pollution differential (front-end control reads first `role`, backend reads last):

```text
POST /update?role=user&role=admin
# or body:  role=user&role=admin
```

Content-type / polyglot (declared JSON, parsed as HTML by a sniffing sink) and Unicode fold (`ﬀ` / fullwidth chars normalising into a blocked keyword after the WAF check) are the other high-yield axes.

## Bypasses and variants

- **Same parser, different config/version**: strictness flags, `lenient` modes, or a library upgrade on only one hop reintroduces a differential.
- **Normalisation-after-check**: the control validates, then a later stage decodes/normalises (percent-decode, Unicode fold, path collapse) into the forbidden value. Order of operations is the bug.
- **Third-parser chains**: cache in front of proxy in front of app can create a three-way split (the Next.js stale-cache chain of 2025 is this shape).
- **Protocol translation**: HTTP/2 to HTTP/1.1 downgrade, gRPC to HTTP, WebSocket upgrade; each translation re-parses and can disagree with the origin framing.

## Detection and defence

- **One parser, or agree on one canonical form**: normalise input to a strict canonical representation once, at the edge, before any check, and forward that canonical form to the sink so both sides read identical bytes.
- **Reject ambiguity, do not repair it**: on duplicate `Host`/`Content-Length`/keys, obsolete folding, or malformed URLs, return an error rather than silently picking one interpretation.
- **Match versions and configs** of parsing libraries across the pipeline; pin and align strictness settings.
- **Validate at the sink, not only the edge**: re-check the value the dangerous component will actually use, after all decoding/normalisation.
- **Key caches on every input that varies the response**; treat unkeyed inputs as a poisoning risk.
- **Detection signals**: requests with duplicated framing headers, mixed `Content-Length`/`Transfer-Encoding`, authority strings containing `@`/backslashes/encoded slashes, and responses whose content disagrees with the cache key.

## Tools

- Burp Suite (Repeater, HTTP Request Smuggler extension, Param Miner for unkeyed inputs and cache probing).
- `curl` / `httpx` with raw request control for framing and encoding tests.
- Protocol/parser fuzzers and differential harnesses comparing two libraries' parse output on the same input.

## Sources

- PortSwigger, "Top 10 Web Hacking Techniques of 2025": "Parser Differentials: When Interpretation Becomes a Vulnerability" (joernchen); plus Unicode normalization, SSRF via HTTP redirect loops, HTTP/2 CONNECT, and Next.js cache-chain entries as members of the family.
- Unifies existing wiki pages: [[http-request-smuggling]], [[http-host-header-attacks]], [[hpp-attacks]], [[web-cache-poisoning]], [[web-cache-deception]], [[ssrf]], [[open-redirect]], [[crlf-injection]], [[reverse-proxy-attacks]], [[nextjs-middleware-bypass]].
