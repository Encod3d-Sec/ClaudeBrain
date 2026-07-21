---
name: hunt-smuggling
description: HTTP request smuggling / desync hunting - CL.TE, TE.CL, TE.TE, CL.0, and HTTP/2 downgrade. Timing-based detection, differential confirmation, no-blind-claims. Wiki-first, FIND schema output.
---

# Hunt: HTTP Request Smuggling

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "http request smuggling desync CL.TE TE.CL" via wiki-search MCP -> read matching page.
```
Core page: [[http-request-smuggling]]. Payload arsenal: `wiki/payloads/smuggling.md`.

**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/web/http-request-smuggling.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target in scope. Smuggling needs a front-end/back-end split (CDN/LB/proxy + origin). Read `Deadends.md`.

## Confirmation Gate (READ FIRST)
**A timing delay alone is a signal, not proof.** Confirm with a differential: a smuggled prefix that changes the *next* request's response (your own follow-up, or a captured victim request). Use Burp Repeater "Send group in sequence (single connection)" or the HTTP Request Smuggler extension. Never report on timing alone.

## OOB Gate (READ FIRST)
**A timing delay alone is a signal, not proof.** Beyond the differential above, an out-of-band callback confirms a desync that reaches an internal component.

NOT confirmation: a back-end read timeout alone, a single slow response. IS confirmation: the captured differential (your smuggled prefix altering the next response), or a DNS/HTTP hit to your unique Burp Collaborator / interactsh subdomain triggered by the smuggled request.

When you plant a blind/OOB payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | smuggling | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique Burp Collaborator / interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind smuggling desync without a HIT row.

## Attack Surface Signals
Front-end that differs from back-end on header parsing: CDN/WAF/LB in front of an origin; HTTP/1.1 keep-alive reused; HTTP/2 to HTTP/1.1 downgrade at the edge. Higher odds where `Transfer-Encoding` and `Content-Length` are both honored somewhere in the chain.

## Methodology
1. **Detect (timing, safe):** send a deliberately malformed TE/CL and watch for a back-end read timeout.
```
# CL.TE probe (front-end uses CL, back-end uses TE) - delays if vulnerable
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

1
A
0

```
```
# TE.CL probe (front-end TE, back-end CL)
Transfer-Encoding: chunked  +  Content-Length: 6 ; body: "0\r\n\r\nX"
```
2. **Confirm (differential):** smuggle a prefix that prepends to the victim's request, then issue a normal request and observe the poisoned response (e.g. your `G` prepended to their path -> 404 on `GET ...`).
3. **TE.TE:** obfuscate the header so one server ignores it (`Transfer-Encoding: xchunked`, ` Transfer-Encoding`, `Transfer-Encoding:\tchunked`, double TE).
4. **HTTP/2:** test H2.CL / H2.TE (smuggle via H2 that downgrades to H1), and H2 request splitting via CRLF in header values.
5. **CL.0 / H2.0:** back-end ignores body -> smuggle a full second request.
6. **Exploit:** capture other users' requests (steal session cookies/headers), bypass front-end auth/path controls, cache-poison via smuggled response, escalate a reflected issue to stored.
7. **Distill to wiki (when confirmed):** if the finding is a reusable obfuscation or H2-desync variant, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/http-request-smuggling.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed (differential proof captured):
```
Create Vulns/Research/FIND-XXX-HIGH-request-smuggling-<host>.md
Add row to Vuln-index.md: | FIND-XXX | CL.TE desync | host | CONFIRMED |
```
Severity: HIGH (request capture / auth bypass / cache poisoning); CRITICAL if it yields admin session theft at scale.

Exhausted (all CL.TE/TE.CL/TE.TE/H2 variants, no timing delta or differential after a full sweep):
```
Append to Deadends.md: - [ ] smuggling <host> -- CL.TE/TE.CL/TE.TE/H2 all clean (single normalising front-end, no desync)
```

Report: Status + files created.
