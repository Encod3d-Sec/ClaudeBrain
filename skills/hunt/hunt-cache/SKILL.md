---
name: hunt-cache
description: Web cache poisoning + cache deception hunting - unkeyed input poisoning, cache-key analysis, path-confusion deception, header/parameter cloaking. Wiki-first, FIND schema output.
---

# Hunt: Web Cache Attacks

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "web cache poisoning deception unkeyed input cache-key path confusion" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[web-cache-poisoning]]. Payload arsenal: `wiki/payloads/web-cache.md`.
Anchors: [[web-cache-deception]], [[web-cache-attacks]]. Related: [[http-host-header-attacks]], [[http-request-smuggling]].

## Attack surface

Needs a cache in front (CDN / Varnish / Cloudflare / Akamai / Fastly, or an app-layer cache). Signals: `Age`, `X-Cache: hit/miss`, `Cache-Control`, `CF-Cache-Status` headers; static-ish responses; responses that reflect a header or param.

**Rank before testing:**

- **Unkeyed headers that reflect** - `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-For`, plus custom headers a page reflects into links/scripts. Highest hit-rate poisoning vector; discover unkeyed inputs with Param Miner.
- **Path / parameter cloaking** - static-looking suffixes and delimiter tricks (`/account/profile.css`, `/account/profile/nonexistent.js`, path-parameter `;`, encoded `%2f`, fat GET) that desync what the cache keys on from what the origin serves. Primary deception vector.
- **CDN edges and normalization gaps** - cache-key normalization (case, trailing slash, duplicate params) differing from origin routing; multi-CDN or origin-vs-edge disagreement.

## Methodology

**Drive load-bearing requests through Burp Repeater** for operator visibility; use Param Miner to enumerate unkeyed headers/params. curl is fine for the quick keyed-vs-unkeyed loop.

1. **Identify the cache + cache key.** Compare `X-Cache`/`Age` across requests; determine what is keyed (usually method + host + path + some query) vs **unkeyed** (most headers, some params). Always attach a unique cache-buster while probing so you never touch a shared key.
2. **Cache poisoning (unkeyed input -> harmful response, then cached for others).**
   - Find an unkeyed input that affects the response (reflected header/param): `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-For`, custom headers (Param Miner to discover).
   - Make it produce harm (XSS / redirect / resource swap), then confirm the **cached** poisoned response is served to a fresh request (cache-buster off) - and cross-session (see confirmation gate).
   - Fat GET, parameter cloaking, and cache-key normalization gaps as variants.
3. **Cache deception (trick the cache into storing a victim's private page).**
   - Request a private page with an appended static-looking suffix/path: `/account/profile.css`, `/account/profile/nonexistent.js`, path-parameter `;`, encoded `%2f`.
   - If the origin returns the private content but the cache stores it as static -> retrieve another user's data unauthenticated.
4. **Confirm impact crosses a trust boundary** - served to other users / discloses private data, not just your own session.
5. **Distill when confirmed** (reusable unkeyed-header or deception-path trick, GENERIC, no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/web-cache-poisoning.md` (deception-path findings: `--target-page techniques/web/web-cache-deception.md`).

## Chaining

An unkeyed input reflected into HTML/JS turns poisoning into **stored XSS served to every client hitting that key** - escalate the payload with `hunt-xss`. A reflected `X-Forwarded-Host` in a redirect or absolute link gives **open redirect / resource swap to all users**. Both raise impact from self-only to mass; prove reach on a benign key, then stop (see stop condition).

## Evasion

When the input looks keyed or filtered: try header-name variants (`X-Forwarded-Host` vs `X-Host` vs `Forwarded`), duplicate/pollute the param so the cache keys one occurrence and the origin reads another, exploit cache-key normalization (case, trailing slash, `%2f`), and use a fat GET (body params on a GET) to smuggle the value past a keyed query string.

## Confirmation gate

Web cache poisoning is a blind / OOB-capable class: the win is a response served to OTHER clients, which you cannot observe from your own session alone.

**NOT confirmation:** your own cached response reflected back to you alone; a single response that might be per-user; an `Age` / `X-Cache: hit` change with no cross-session retrieval; the payload echoed in your own request.

**IS confirmation:** a poisoned or deceived response served to a DIFFERENT session and reproduced in a clean session (fresh profile, no cached state, cache-buster off); or an OOB callback to your unique Burp Collaborator / interactsh subdomain from a resource you injected into the cached page - a Collaborator-pointed unkeyed header confirms the poisoning reaches the cache and is loaded by other clients.

When you plant a blind/OOB payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | cache | <date> | waiting | |` (columns: token | sink | class | planted | status | source; token = your unique Burp Collaborator / interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row in `targets/<eng>/oob.md` is the gate to scaffold the FIND. Do NOT claim a blind cache poisoning without cross-session proof or a HIT row.

## Stop condition (traffic-affecting)

Per `hunt-core`, cache poisoning is a traffic-affecting primitive: poisoning the shared/production cache can serve malicious content to every real user who hits that key. Demonstrate on a benign, self-scoped cache key (a unique cache-buster or your own path) and STOP at proof. Do not mass-poison a shared key, and do not leave a live payload sitting in the production cache.

## Severity

HIGH (stored XSS / redirect to all users, or PII disclosure via deception); CRITICAL if it yields mass account takeover; MEDIUM if self-only / weak impact.

## Deadends

```
Append: - [ ] web-cache <host> -- key includes host+all reflective params; deception suffixes not cached (Cache-Control: private)
```
