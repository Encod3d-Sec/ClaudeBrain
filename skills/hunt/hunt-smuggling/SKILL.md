---
name: hunt-smuggling
description: HTTP request smuggling / desync hunting - CL.TE, TE.CL, TE.TE, CL.0, and HTTP/2 downgrade. Timing-based detection, differential confirmation, no-blind-claims. Wiki-first, FIND schema output.
---

# Hunt: HTTP Request Smuggling

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "HTTP request smuggling desync CL.TE TE.CL TE.TE CL.0 HTTP/2 downgrade" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[http-request-smuggling]]. Payload arsenal: `wiki/payloads/smuggling.md`.
Anchors: [[reverse-proxy-attacks]].

## Attack surface signals

Smuggling needs a front-end that parses headers differently from the back-end: a CDN/WAF/LB in
front of an origin, HTTP/1.1 keep-alive reused across users, or an HTTP/2 edge that downgrades to
HTTP/1.1. Odds rise wherever both `Transfer-Encoding` and `Content-Length` are honored somewhere
in the chain.

**Rank before probing.** Not all front-end/back-end pairs are equally likely:

- **HTTP/2 edge downgrading to HTTP/1.1 origin** - H2.CL / H2.TE re-open a surface a hardened H1
  front-end closes; highest yield on modern stacks.
- **Multiple hops in the chain** - CDN -> WAF -> LB -> origin; each added parser is another chance
  for two of them to disagree.
- **Mismatched server software front vs back** - e.g. a normalising proxy in front of a lenient
  app server, or vice versa.
- **Connection reuse to the back-end** - a poisoned prefix only reaches a victim if the back-end
  pools/keep-alives the connection across requests.
- **Endpoints behind the edge auth/path filter** - a desync that bypasses a front-end control is
  worth more than one that does not reach anything privileged.

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
2. **Confirm (differential):** smuggle a prefix that prepends to the victim's request, then issue a normal request and observe the poisoned response (e.g. your `G` prepended to their path -> 404 on `GET ...`). See the confirmation gate below - a timing delay alone is never the finding.
3. **TE.TE:** obfuscate the header so one server ignores it (`Transfer-Encoding: xchunked`, ` Transfer-Encoding`, `Transfer-Encoding:\tchunked`, double TE).
4. **HTTP/2:** test H2.CL / H2.TE (smuggle via H2 that downgrades to H1), and H2 request splitting via CRLF in header values.
5. **CL.0 / H2.0:** back-end ignores body -> smuggle a full second request.
6. **Exploit:** capture other users' requests (steal session cookies/headers), bypass front-end auth/path controls, cache-poison via smuggled response, escalate a reflected issue to stored.
7. **Distill when confirmed** - reusable obfuscation or H2-desync variant, GENERIC, no client host: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/http-request-smuggling.md`

**Drive it through Burp** for operator visibility. Use Burp Repeater "Send group in sequence
(single connection)" for the differential and the HTTP Request Smuggler extension for the sweep;
push each load-bearing smuggled request into Repeater rather than leaving it in a curl loop.

## Confirmation gate

**NOT confirmation:** a single slow response or timing noise alone; a back-end read timeout by
itself; a malformed request the front-end simply rejects; a delay you have not reproduced. A
single timing observation is a signal to investigate, never proof of a desync.

**IS confirmation:** a reliable differential - a smuggled prefix that changes the *next* request's
response (your own follow-up, or a captured victim request), reproduced on a clean connection; or
a consistent timing delta reproduced across several runs and matched to a specific desync variant;
or a DNS/HTTP hit to your unique Burp Collaborator / interactsh subdomain fired by a
Collaborator-pointed smuggled request.

**Blind / OOB desync.** When you plant a Collaborator-pointed smuggled request, append a row to
`targets/<eng>/oob.md`: `| <token> | <sink url+param> | smuggling | <date> | waiting | |`
(columns: token | sink | class | planted | status | source; token = your unique Burp
Collaborator / interactsh label). The recon-capture hook auto-correlates the incoming callback to
flip the row to HIT and SessionStart surfaces HITs; a HIT row is the gate to scaffold the FIND.
**Do NOT claim a blind** smuggling desync without the captured differential or a HIT row.

## Chaining

A confirmed desync is a delivery primitive, not the endpoint. Chain it:

- **Smuggled response -> cache poisoning.** Poison a shared cache with a smuggled response so it
  serves to every user; hand off to `hunt-cache`.
- **Request hijack.** Capture the next user's full request (session cookie, auth header, CSRF
  token) by smuggling a prefix that appends their request to a body you read back.
- **Front-end control bypass -> stored.** Smuggle past an edge auth/path filter to reach an
  internal endpoint, or escalate a reflected issue to stored via a poisoned response.

## Evasion

If the direct CL/TE probe is normalised clean, the desync is often still there behind
obfuscation - work the TE.TE variants (step 3) and the HTTP/2 downgrade (step 4), which re-opens
the surface a hardened HTTP/1.1 front-end closes. Header casing, line-folding, and bare-CR/LF
tricks beyond those live in `wiki/payloads/smuggling.md`.

## Severity

| Impact | Typical |
|---|---|
| Captured victim requests (session cookie / auth header) at scale | critical |
| Admin session theft | critical |
| Front-end auth / path-control bypass | high |
| Cache poisoning via smuggled response | high |
| Reflected escalated to stored via poisoning | high |

Rated on demonstrated impact per `hunt-core`. A desync you can trigger but cannot yet show
capturing a victim request or poisoning a response is a mechanism, not the severity ceiling.

## Deadends

```
Append: - [ ] smuggling on <host> -- CL.TE/TE.CL/TE.TE/CL.0/H2 all clean
              (single normalising front-end, no timing delta or differential after a full sweep)
```

Record which variants you swept, not just that it failed. The next pass needs to know the boundary.
