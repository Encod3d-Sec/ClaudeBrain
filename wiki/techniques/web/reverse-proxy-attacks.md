---
title: "Reverse Proxy Misconfigurations"
type: technique
tags: [nginx, proxy, path-traversal, ssrf, ssti, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-17
sources: [payloadsallthethings-reverseproxy, orange-confusion-attacks]
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
