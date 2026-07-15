---
title: "ReDoS (Regular-Expression DoS + Blind Regex Exfiltration)"
type: technique
tags: [redos, dos, regex, exfiltration, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# ReDoS (Regular-Expression DoS + Blind Regex Exfiltration)

Backtracking engines (PCRE, Java `java.util.regex`, Python `re`, JS `RegExp`) blow up
super-linearly on crafted input against "evil" patterns (nested/overlapping quantifiers). Two
offensive uses: availability DoS, and a data-exfiltration oracle when you control the regex a secret
is matched against.

## Availability
When you only control input, find endpoints with complex validators (email, URL,
sanitizers) and feed doubling-length strings (2^k) while measuring latency; exponential growth
confirms the primitive. When you control the pattern (stored validation rules, WAF rules), ReDoS is
usually trivial. Engines built on finite automata (RE2/RE2J/RE2JS, Rust regex crate) are immune, so
pivot if you hit them.

## Blind regex exfiltration (CTF/bug bounty)
If a secret (flag, token) is matched against a regex you
influence, craft a pattern that catastrophically backtracks ONLY when a guessed prefix matches, and
measure response time to leak the secret char by char, e.g. `^(?=<known_prefix>)((.*)*)*salt$`.

Tools: doyensec/regexploit (find evil regexes + auto-generate inputs), devina.io/redos-checker,
davisjam/vuln-regex-detector, tjenkinson/redos-detector. Payload strings: [[redos]] (payloads).

## Sources
- HackTricks (pentesting-web)
