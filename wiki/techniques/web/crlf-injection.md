---
title: "CRLF Injection (HTTP Response Splitting)"
type: technique
tags: [crlf, injection, web, xss, header-injection]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-crlfinjection]
---

# CRLF Injection (HTTP Response Splitting)

## What it is

Injecting Carriage-Return (`\r`/`%0D`) + Line-Feed (`\n`/`%0A`) into a value that the server writes into an HTTP response. Because CRLF separates HTTP headers (and the blank line `\r\n\r\n` ends them), the attacker can add headers or split off a body - leading to header injection, XSS, open redirect, cache poisoning, and log forging. Related: [[xss]], [[open-redirect]], [[web-cache-poisoning]].

## How it works / where found
Any user input reflected into a **response header**: `Location` (redirects), `Set-Cookie`, custom headers, `Link`, and reflected values in 3xx/error responses. Common sinks: `?url=`/`?redirect=`/`?next=`, language/region params, and anything echoed into a header. One CRLF adds a header; two (`%0d%0a%0d%0a`) start the body.

## Methodology
### Header injection / session fixation
```text
value%0D%0ASet-Cookie:%20admin=true
```
### XSS (split into the body)
```text
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<svg%20onload=alert(document.domain)>
```
### Open redirect
```text
%0d%0aLocation:%20https://attacker.com
```
### Other impact
Inject `Set-Cookie` (fixation), forge log lines (log injection / poisoning), or split a cacheable response to poison the cache ([[web-cache-poisoning]]).

## Filter bypass
Some servers/browsers downcast out-of-range UTF-8 by stripping high bytes back to ASCII, smuggling CR/LF past naive filters:
| UTF-8 | Hex | Downcasts to |
| --- | --- | --- |
| `嘊` | `%E5%98%8A` | `%0A` (`\n`) |
| `嘍` | `%E5%98%8D` | `%0D` (`\r`) |
| `嘼` | `%E5%98%BC` | `%3C` (`<`) |
| `嘾` | `%E5%98%BE` | `%3E` (`>`) |
```text
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8D...嘼svg/onload=alert(document.domain)嘾
```
Also try: bare `%0A`, `%E5%98%8A`, `%0D%0A` vs `%0A` only (some need just LF), and double-encoding `%250d%250a`.

## Detection
Inject `%0d%0aFoobar:%20test` into header-reflected params and look for `Foobar: test` in the response headers (Burp). `crlfuzz`/nuclei `http/cves`+`crlf` templates automate it.

## Real-world
A long-running bug-bounty class: CRLF in `Location`/redirect params escalates to reflected XSS, session fixation, and (when the response is cacheable) cache poisoning. Many CVEs in proxies/load balancers and frameworks that did not strip CR/LF from header values.

## Detection and defence
Strip/reject CR and LF (and their encodings) from any value placed in a header; use framework header APIs that disallow control chars (modern servers reject them); allowlist redirect targets; never reflect raw input into `Location`/`Set-Cookie`.

## Tools
`crlfuzz`, `nuclei`, Burp Repeater, `Param Miner`. See [[xss]], [[open-redirect]], [[http-request-smuggling]].

## Sources
- PayloadsAllTheThings - CRLF Injection
