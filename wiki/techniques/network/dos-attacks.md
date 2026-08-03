---
title: "Regular Expression Denial of Service (ReDoS)"
type: technique
tags: [redos, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings-redos]
---

# Regular Expression Denial of Service (ReDoS)

## What it is
ReDoS is a type of Denial of Service (DoS) attack that exploits inefficient regular expressions. When an engine evaluates a complex regex against a specifically crafted string, it can suffer from catastrophic backtracking, consuming immense CPU resources and causing the application to hang or crash.

## Evil Regex Methodology
An "Evil Regex" typically contains:
- Grouping with repetition.
- Inside the repeated group, there is further repetition or alternation with overlapping characters.

**Examples of vulnerable regex patterns:**
- `(a+)+`
- `([a-zA-Z]+)*`
- `(a|aa)+`
- `(.*a){x}` for x > 10

**Exploitation:**
Provide a long string that nearly matches the pattern but fails at the very end. This forces the regex engine to backtrack and evaluate every possible permutation of the grouping.
*Payload:* `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!`

## Tools
- [tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector) - A CLI and library which tests with certainty if a regex pattern is safe from ReDoS attacks.
- [doyensec/regexploit](https://github.com/doyensec/regexploit) - Find regular expressions which are vulnerable to ReDoS.
