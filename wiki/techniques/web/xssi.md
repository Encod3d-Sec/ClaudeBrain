---
title: "XSSI (Cross-Site Script Inclusion)"
type: technique
tags: [xssi, cors, information-disclosure, jsonp, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-21
sources: [hacktricks-web]
---

# XSSI (Cross-Site Script Inclusion)

Quick payloads: [[payloads/xssi]].

Scripts are exempt from Same-Origin Policy, so `<script src>` sends ambient cookies cross-origin
and the response body becomes readable to the including page. Any endpoint that returns
credential-scoped data as JS/JSONP (or as a non-JS file loadable as a script) can leak that data to
an attacker page. Four classes: static JS, static-authenticated JS, dynamic JS, and non-script
(CSV/JSON) XSSI.

## Detection and exploitation
Request a dynamic-JS endpoint with and without cookies and diff the responses
(Burp DetectDynamicJS). If confidential data lands in a global var, read it directly after
inclusion. If it is a JSONP response, define the callback (or override a global object's method)
before including the script to capture the argument. For non-global vars, prototype tampering can
leak them (override `Array.prototype.slice` and exfiltrate `this`). Non-script XSSI can leak CSV or
UTF-7-encoded JSON loaded via `<script charset="UTF-7">`.

Bappstore extension: DetectDynamicJS. Payload strings: [[xssi]] (payloads). Related: [[cors]].

## Sources
- HackTricks (pentesting-web)

## Related

- [[xss]] (both abuse cross-origin script inclusion in the victim page)
- [[cors-sop]] (SOP and CORS govern the cross-origin reads XSSI steals)
- [[xs-leak]] (XSSI is a classic cross-site data leak)
