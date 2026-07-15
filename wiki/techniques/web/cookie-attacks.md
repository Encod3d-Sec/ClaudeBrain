---
title: "Cookie Tossing, Jar Overflow, Prefix Bypass, Sandwich"
type: technique
tags: [cookies, session, csrf, prefix-bypass, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# Cookie Tossing, Jar Overflow, Prefix Bypass, Sandwich

Session-integrity attacks that live in the browser/server cookie-parsing gap (RFC 6265 octet vs
string). Preconditions for tossing: attacker controls a subdomain or has XSS on one. Complements
[[session-management-attacks]] (adds the tossing/prefix/sandwich primitives, not just fixation).

## Primitives
- Cookie tossing: from a subdomain set `document.cookie="session=...; domain=.example.com;
  Path=/specific"`. A more-specific Path or an older cookie is sent first; most apps read only the
  first value, letting you fixate a session/CSRF-token or hijack an OAuth flow on chosen paths.
- Cookie jar overflow: browsers cap cookies per domain; overflow the jar to evict the legit
  (even HttpOnly) cookie, then set your own. Used to bypass "reject two same-name cookies" defenses
  and to overwrite HttpOnly cookies.
- `__Host-`/`__Secure-` prefix bypass: prefixes are enforced only at set-time in the browser, then
  the server re-parses. Forge protected cookies from a subdomain by (a) prepending a Unicode
  whitespace codepoint that the backend later trims (Django `str.strip()` normalizes U+0085,
  U+00A0, U+2000-200A, etc. back to `__Host-`), (b) legacy `$Version=1` cookie splitting on
  Tomcat/Jetty/Undertow, or (c) PHP name-char normalization. Duplicate-name "last wins" then makes
  the attacker cookie win. Burp bambda: CookiePrefixBypass. Cross-test browsers (Safari blocks
  multibyte whitespace but allows U+0085/U+00A0).
- Cookie sandwich: steal HttpOnly cookies by trapping the victim cookie between a `$Version=1`
  cookie and a reflected cookie with an unclosed double-quote, so legacy quoted-string parsing folds
  the HttpOnly value into a reflected parameter.
- Empty-name cookie (`document.cookie="=a=b"`) lets you inject/overwrite another cookie server-side.

Payload strings: [[session]] (payloads). Related: [[csrf]].

## Sources
- HackTricks (pentesting-web)
