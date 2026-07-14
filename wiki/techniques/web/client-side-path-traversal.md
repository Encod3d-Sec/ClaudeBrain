---
title: "Client-Side Path Traversal (CSPT)"
type: technique
tags: [web, cspt, path-traversal, client-side, csrf, idor]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [doyensec-cspt, cspt-research-notes]
---

# Client-Side Path Traversal (CSPT)

## What it is
Client-Side Path Traversal (CSPT) is a 2024-prominent class where attacker-controlled input is concatenated into a URL path by front-end JavaScript before the browser sends a request to the application's own API. By injecting `../` (or encoded variants), the attacker redirects that same-origin request to a different, attacker-chosen API endpoint, turning a benign client feature into a CSRF-like primitive (CSPT2CSRF) or a reflected-data sink.

## How it works
Front-end code often builds API URLs from user-influenced values, for example `fetch('/api/users/' + id + '/profile')`. If `id` is attacker-controlled (URL parameter, postMessage, stored field) and not sanitised, `id = ../../admin/promote` traverses the path so the browser issues `/api/admin/promote` as the authenticated victim. Because the request is genuinely same-origin and carries the victim's cookies/tokens, it bypasses CSRF defences that rely on same-origin or SameSite. The sink can be a state-changing call (CSPT2CSRF) or a read whose response is rendered (reflected XSS or data leak).

## Attack phases
Exploitation; CSRF/IDOR-style state change or data exfiltration in the victim's session.

## Prerequisites
- Front-end JS that builds a same-origin request path from attacker-influenced input without normalising `../`.
- A reachable sensitive endpoint on the same origin to traverse to.
- For CSPT2CSRF: the target endpoint accepts the method/body the gadget sends and lacks an unguessable token the attacker cannot supply.

## Methodology
1. Map client-side request builders: search JS for string concatenation into `fetch`/`XMLHttpRequest`/`axios` URLs using input you control.
2. Inject `../` into that input and confirm the outbound request path changes (DevTools Network tab).
3. Find a same-origin sink endpoint reachable by traversal that performs a sensitive action or returns sensitive data.
4. Build the gadget: deliver the malicious input (link, stored value, postMessage) so the victim's browser issues the traversed request in their session.
5. Confirm the action or leak (CSPT2CSRF state change, or reflected response).

## Key payloads / examples
```
# input consumed by fetch('/api/items/' + input)
../../admin/users/1/role?value=admin
%2e%2e%2f%2e%2e%2fadmin%2fpromote      (encoded ../../ if the builder or server decodes)
# CSPT2CSRF: traverse a GET-driven feature into a state-changing same-origin endpoint
```

## Bypasses and variants
- Encoded traversal (`%2e%2e%2f`, double-encoding) where the builder or server decodes once.
- CSPT2CSRF: chain into a same-origin endpoint the framework treats as trusted (no token), achieving CSRF despite SameSite/Origin checks.
- Reflected CSPT: the traversed read response is rendered into the DOM (XSS or data leak).

## Detection and defence
- Normalise and validate client-supplied path segments; reject `..` and encoded variants before building URLs.
- Use allowlisted identifiers (numeric ids) and build URLs from fixed templates, not string concatenation.
- Keep server-side authorization on every endpoint; do not assume a same-origin request implies an intended action.

## Tools
Browser DevTools and Burp. See [[path-traversal-lfi]], [[csrf]], and [[access-control]].

## Sources
- Doyensec / Maxence Schmitt, Client-Side Path Traversal (CSPT2CSRF) research (slug: doyensec-cspt).
- CSPT testing notes (slug: cspt-research-notes).
