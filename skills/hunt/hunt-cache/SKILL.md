---
name: hunt-cache
description: Web cache poisoning + cache deception hunting - unkeyed input poisoning, cache-key analysis, path-confusion deception, header/parameter cloaking. Wiki-first, FIND schema output.
---

# Hunt: Web Cache Attacks

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "web cache poisoning deception unkeyed input" via wiki-search MCP -> read matching page.
```
Core pages: [[web-cache-poisoning]], [[web-cache-deception]], [[web-cache-attacks]]. Related: [[http-host-header-attacks]], [[http-request-smuggling]]. Payload arsenal: `wiki/payloads/web-cache.md`.

**Self-heal:** wiki query empty -> create stub `wiki/techniques/web/web-cache-poisoning.md` before proceeding.

## Scope Check
- Confirm in scope. Needs a cache in front (CDN/Varnish/Cloudflare/Akamai/Fastly or app cache). Read `Deadends.md`.

## Attack Surface Signals
Cache headers (`Age`, `X-Cache: hit/miss`, `Cache-Control`, `CF-Cache-Status`), static-ish responses, CDN in front, responses that reflect headers/params.

## Methodology
1. **Identify the cache + cache key:** compare `X-Cache`/`Age` across requests; determine what is keyed (usually method + host + path + some query) vs **unkeyed** (most headers, some params).
2. **Cache poisoning (unkeyed input -> harmful response, then cached for others):**
   - find an unkeyed input that affects the response (reflected header/param): `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Host`, `X-Forwarded-For`, custom headers (use Param Miner to discover).
   - make it produce harm (XSS/redirect/resource swap), confirm the **cached** poisoned response is served to a fresh request (clean cache-buster off).
   - fat GET, parameter cloaking, and cache-key normalization gaps as variants.
3. **Cache deception (trick the cache into storing a victim's private page):**
   - request a private page with an appended static-looking suffix/path: `/account/profile.css`, `/account/profile/nonexistent.js`, path-parameter `;`, encoded `%2f`.
   - if the origin returns the private content but the cache stores it as static -> retrieve another user's data unauthenticated.
4. Confirm impact crosses a trust boundary (served to other users / discloses private data), not just your own session.
5. **Distill to wiki (when confirmed):** if the finding is a reusable unkeyed-header or deception-path trick, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/web-cache-poisoning.md` (deception-path findings: `--target-page techniques/web/web-cache-deception.md`). Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed (poisoned response served to a clean request, or a victim's private data cached):
```
Create Vulns/Research/FIND-XXX-<SEV>-web-cache-<poisoning|deception>-<host>.md
Add row to Vuln-index.md: | FIND-XXX | cache poisoning via X-Forwarded-Host | host | CONFIRMED |
```
Severity: HIGH (stored XSS/redirect to all users, or PII disclosure via deception); CRITICAL if it yields mass account takeover; MEDIUM if self-only / weak impact.

Exhausted (cache key includes the input, no unkeyed reflective input, deception suffixes all 404/no-store):
```
Append to Deadends.md: - [ ] web-cache <host> -- key includes host+all reflective params; deception suffixes not cached (Cache-Control: private)
```

Report: Status + files created.
