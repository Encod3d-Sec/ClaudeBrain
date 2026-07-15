---
title: "Reverse Proxy Misconfigurations"
type: technique
tags: [nginx, proxy, path-traversal, ssrf, ssti, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-15
sources: [payloadsallthethings-reverseproxy, orange-confusion-attacks, hacktricks-web]
---

# Reverse Proxy Misconfigurations

## What it is

Reverse proxies (Nginx, Apache, HAProxy, Traefik, Envoy, Caddy, CDNs) forward client requests to backends and add caching/LB/auth. Misconfigurations - alias traversal, trusting client headers, path-normalization gaps, or `proxy_pass` with user input - yield access-control bypass, file read, SSRF, and SSTI. Related: [[http-request-smuggling]], [[ssrf]], [[ssti]].

## How it works / where found
The proxy and backend can disagree on the path, the trusted client IP, or where a `location` maps. Attackers exploit that gap. Fingerprint the proxy (`Server`, error pages, header behavior) first.

## Methodology
### Client-IP / trust header spoofing
If the proxy does not strip these, you spoof origin (bypass IP allowlists / rate limits / admin-by-IP):
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1      (Akamai)   X-Forwarded-Host / X-Original-URL / X-Rewrite-URL
```
`X-Original-URL`/`X-Rewrite-URL` can reach paths the proxy ACL blocks (Symfony/IIS/Nginx rewrite cases).

### Nginx off-by-slash (alias traversal)
`location /styles` (no trailing slash) + `alias /path/css/;` -> `/styles../secret.txt` resolves to `/path/css/../secret.txt`. Missing root location -> `/nginx.conf` served from the global `root`.

### Path normalization / ACL bypass
The proxy authorizes one path, the backend normalizes another:
```
/admin..;/   /admin%2f..%2f   /admin%00   /%2e/admin   //admin   /admin/.   /ADMIN
```
`bypass-url-parser` automates these against a protected endpoint.

### Caddy / template SSTI
`templates` interpolating a client header -> Go SSTI:
```bash
curl -H 'Referer: {{readFile "etc/passwd"}}' http://target/
```
`{{env "VAR"}}`, `{{listFiles "/"}}`, `{{readFile "..."}}`.

### proxy_pass SSRF
`proxy_pass http://$host...` or user-controlled upstream -> SSRF into internal services ([[ssrf]]).

### Apache HTTP Server Confusion Attacks (Orange Tsai, Black Hat USA 2024)
Within one Apache httpd `request_rec`, the fields `r->filename`, `r->handler`, and `r->content_type` can be coerced into each other, and path/DocumentRoot handling is ambiguous. Three classes:
- Filename confusion: modules treat `r->filename` as both a URL and a file path; a `RewriteRule` mapping may access both relative and absolute paths, escaping DocumentRoot (ACL bypass, file read outside web root).
- DocumentRoot confusion: requests resolve against an unexpected root.
- Handler confusion: coercing `r->handler` / `r->content_type` makes a request run through a different handler, leading to SSRF or RCE (for example forcing a file through a scripting handler or `mod_proxy`).

Patched CVEs: CVE-2024-38472 (UNC SSRF), CVE-2024-39573 (mod_rewrite proxy handler), CVE-2024-38477 (mod_proxy DoS), CVE-2024-38476 (backend output to handler execution). Fixed in httpd 2.4.59/2.4.60. Test: fingerprint httpd version, probe `RewriteRule` behaviour, encoded path segments, and handler/content-type coercion.

## HTTP Connection Contamination (first-request routing)
Browsers coalesce a single HTTP/2+ connection across hostnames that share an IP and a TLS cert
(commonly a wildcard `*.example.com`). If the reverse proxy uses first-request routing (routes the
whole connection to the back-end chosen by the first request), later requests to a different vhost
on the coalesced connection are misrouted to the wrong back-end. So a low-value host
(`wordpress.example.com`) with XSS can be reached by a browser request intended for
`secure.example.com`, turning a same-site low-severity bug into a cross-service one without MITM.

Test with coalescing observed in Chrome Network tab / Wireshark:
```javascript
fetch("//sub1.example.com/", {mode:"no-cors", credentials:"include"}).then(() => {
  fetch("//sub2.example.com/", {mode:"no-cors", credentials:"include"})
})
```
Preconditions: shared IP + wildcard/multi-SAN cert + first-request routing. Attack surface widens
under HTTP/3 (relaxes the IP-match requirement). Fix: avoid first-request routing; scope certs.

## Hop-by-hop header abuse
Hop-by-hop headers apply to a single transport hop and must be stripped by a compliant proxy before forwarding. The standard set is `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`, `Proxy-Authenticate`. Critically, the `Connection` header lets a client mark ANY additional header as hop-by-hop. A proxy that honours this but fails to re-add or validate the named header creates a bypass: the backend never sees a header it expected.

```http
# Force the proxy to drop X-Forwarded-For so the backend treats the request
# as coming directly from a trusted proxy IP (IP-ACL / geofence bypass)
GET /admin HTTP/1.1
Host: target
Connection: close, X-Forwarded-For
X-Forwarded-For: 1.2.3.4
```

Other headers to nominate as hop-by-hop: session/auth headers the backend trusts (`Cookie`, custom `X-Auth-*`), and cache-key headers for cache poisoning (mark a header the cache keys on so it is stripped after the response is stored). Detection: send a request with and without `Connection: close, <header>` and diff the responses; a behaviour change means the proxy is stripping it. Automate with a Burp Intruder sweep over candidate header names.

## Real-world
Nginx alias traversal and `X-*-URL` ACL bypass are recurring CVEs/bug-bounty finds; CDN+origin path-normalization differences enable auth bypass and request smuggling ([[http-request-smuggling]]).

## Detection and defence
Always trailing-slash `alias`/`location`; define an explicit `/` root; strip/normalize untrusted `X-Forwarded-*`/`X-*-URL` at the edge and only trust them from known proxies; keep proxy + backend on identical path normalization; never put user input in `proxy_pass`; lint config with `gixy`.

## Tools
- [yandex/gixy](https://github.com/yandex/gixy) - Nginx config analyzer.
- [shiblisec/Kyubi](https://github.com/shiblisec/Kyubi) - alias-traversal finder.
- [laluka/bypass-url-parser](https://github.com/laluka/bypass-url-parser) - ACL/path bypass fuzzer.

## Sources
- PayloadsAllTheThings - Reverse Proxy
