---
title: "Type Juggling & Magic Hashes"
type: technique
tags: [exploitation, php, type-juggling, authentication, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-typejuggling]
---

# Type Juggling & Magic Hashes

## What it is

In loosely typed languages (PHP especially), the loose comparison operators (`==`, `!=`) coerce operands before comparing, producing surprising equalities. Attackers abuse this to bypass authentication, signature/token checks, and access control where code uses `==` instead of strict `===`. Pairs with [[authentication-attacks]]; the JSON variant overlaps [[nosql-injection]].

## How it works

`==` triggers PHP's juggling rules: numeric strings cast to int, `"0e..."` strings parse as scientific notation = 0, and many string-vs-number/bool comparisons return `true`. If a secret check is `if ($user_token == $expected)`, an attacker controls one side and forces equality.

## Loose comparison examples
| Statement | Output |
| --------- | ------ |
| `'0010e2' == '1e3'` | true |
| `'0xABCdef' == ' 0xABCdef'` | true (PHP 5) / false (PHP 7) |
| `'123a' == 123` | true |
| `'abc' == 0` | true (PHP < 8) |
| `'' == 0 == false == NULL` | true |

PHP 8 fixed many of these (non-numeric string vs int now compares as strings), but countless older/embedded codebases remain vulnerable.

## Magic hashes
If a hash string is `0e` followed by **only digits**, PHP reads it as `0 * 10^X = 0`. Two different inputs whose hashes both match `^0e\d+$` are loosely equal - so `$known_hash == $user_hash` can be bypassed without knowing the secret.

| Hash | Magic input | Hash result |
| --------- | ------------ | ----------------- |
| MD5 | `240610708` | `0e462097431906509019562988736854` |
| MD5 | `QNKCDZO` | `0e830400451993494058024219903391` |
| SHA1 | `10932435112` | `0e07766915004133176347055865026311692244` |

**Exploit:** where a password/token is checked as `md5($input) == $stored` and `$stored` is itself a magic hash (or you can influence it), submit a known magic-hash collision string. Find more with `hashcat`/scripts that brute for `^0e\d+$`.

## Other juggling primitives
- **`strcmp()` with an array:** `strcmp($_GET['x'], $secret)` returns `NULL` when `x[]=` is an array; `NULL == 0` -> auth bypass. Same for `strpos`, `preg_match` (returns false), `in_array`/`switch` loose matching.
- **`json_decode` type confusion:** send `{"password": true}` or a number where a string is expected -> `==` against a hash/string may pass; classic JSON login bypass (also a [[nosql-injection]] operator vector in Node/Mongo).
- **`is_numeric` / `intval` gaps:** leading whitespace, hex, or `+`/`-` slipping past weak numeric checks.
- **JavaScript** has its own coercion (`[]==![]` is true, `'' == 0`); abuse in JS auth/equality checks.

## Methodology
Grep the codebase for the bug: `==`/`!=` near `password`, `token`, `hash`, `hmac`, `strcmp`, `==` after `md5(`/`sha1(`. Test login/reset/verify endpoints with: `0`, `0e1`, a magic-hash string, `param[]=` (array), and JSON type swaps. Confirm a bypass crosses an auth/authz boundary.

## Detection and defence
Use strict comparison (`===`/`!==`) and constant-time `hash_equals()` for secrets/HMACs; cast/validate types before comparing; never compare hashes with `==`; upgrade to PHP 8. SAST rule: flag `==` between a request value and a secret. Find with [[semgrep]] (`$X == md5(...)`).

## Sources
- PayloadsAllTheThings - Type Juggling
