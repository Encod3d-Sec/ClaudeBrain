---
title: "Encoding & Transformations"
type: technique
tags: [bypass, evasion, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings]
---

# Encoding and Transformations

## What it is
Encoding and transformations change how data is represented. Attackers use these methods as gadgets to bypass input filters, WAFs, or sanitization routines.

## Unicode Normalization
Unicode normalization converts text into a standardized form. Vulnerabilities arise when an application sanitizes input, but a subsequent system or library normalizes it into a malicious payload.

### Common Normalization Bypasses
*   `‥` (U+2025) normalizes to `..` -> Path Traversal (`‥/‥/etc/passwd`)
*   `＇` (U+FF07) normalizes to `'` -> SQL Injection (`＇ or ＇1＇=＇1`)
*   `＜` (U+FF1C) normalizes to `<` -> XSS (`＜img src=a＞`)
*   `ｐ` (U+FF50) normalizes to `p` -> Extension Bypass (`shell.ｐʰｐ`)

## Punycode
Punycode represents Unicode characters using ASCII (used in IDNs).
*   Visible: `раypal.com` (Cyrillic 'р')
*   Actual: `xn--ypal-43d9g.com`
*   In some SQL collations (like `utf8mb4_0900_as_cs`), similar characters are treated as equal (`'a' = 'ᵃ'`), which can bypass password resets or OAuth checks.

## Base64
Often used to smuggle payloads past simple WAFs.
```bash
echo -n "payload" | base64
```

## External Variable Modification (PHP)
In PHP, functions like `extract($_GET)` import user-controlled data into the global scope. By default (`EXTR_OVERWRITE`), this overwrites existing variables.
```php
// If extract is used:
extract($_GET);
// Attackers can pass ?authenticated=1 or ?page=../../etc/passwd
```
**Fix:** Always use `extract($_GET, EXTR_SKIP)`.
