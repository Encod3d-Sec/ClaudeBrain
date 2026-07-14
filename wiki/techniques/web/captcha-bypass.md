---
title: "CAPTCHA-Protected Login Brute Force"
type: technique
tags: [web, brute-force, captcha, automation, authentication]
date_created: 2026-07-04
date_updated: 2026-07-04
sources: [thm-capture-returns]
---

## Purpose

Automating a login brute force when the app gates attempts behind a CAPTCHA after N
failures. The captcha is an anti-automation speed bump, not an unsolvable wall: the two
common types (geometric shape, distorted text/arithmetic) are both scriptable, so you keep
the wordlist attack running unattended. Pattern verified on THM "Capture Returns".

## Recognize the gate

- After ~3 failed logins the login form is replaced by a challenge: "solve N captchas in a
  row", an inline `data:image/png;base64,...` image, and a `<input name="captcha">`.
- State is often **per-IP, server-side, cookieless** (no token to steal, no answer leaked in
  cookie / HTML comment / hidden field / PNG `tEXt` chunk; check those first anyway, it is the
  cheapest bypass).
- Per-answer oracle: a wrong answer echoes an "Invalid captcha" (or similar) marker on the next
  page; a correct one does not. Use it to score your solver live.

## Solve the captcha types

**Geometric shape (circle / square / triangle).** No OCR. Threshold foreground, take the
bounding box, and read the edge profile of the outline:
- top row AND bottom row AND both side columns nearly full -> **square**
- bottom row full, top rows empty (apex) -> **triangle**
- otherwise -> **circle**
This is ~100% reliable and dependency-light (numpy + Pillow).

**Distorted text / arithmetic ("value").** Do not fight it with tesseract (it folds the noise
line into a spurious trailing digit). Use `ddddocr` (pip install), which is purpose-built for
these:
```python
import ddddocr; ocr = ddddocr.DdddOcr(show_ad=False)
raw = ocr.classification(png_bytes)          # e.g. "339*10=?" -> "339*10=2"
import re
m = re.search(r'(\d+)\s*([*xX+\-])\s*(\d+)', raw)   # it is a MATH problem: submit the RESULT
ans = eval(f"{m[1]}{m[2].replace('x','*')}{m[3]}") if m else re.sub(r'\D','',raw)
```
Key insight: the field is named "value" and asks you to *solve* it - submit the computed
answer, not the transcribed expression.

## The "N in a row" gate

Solving N consecutively (wrong resets the counter) grants a short window of evaluated login
attempts (often 2-3) before the wall returns. If shapes are free (100% solved) and only every
other captcha is a hard type, you only need ONE hard captcha correct to advance past a wall.

## Brute-force state machine

Per guess, drive: POST `username`+`password`; if the response is a captcha, auto-solve toward
the gate (POST `captcha=<ans>` in a loop until it 302s back to /login), then **re-POST the
guess** (it was not evaluated while gated); classify the evaluated response.

**Success detection (the classic false-negative):** a valid login may return **HTTP 200 with a
session cookie set**, NOT a redirect. Keying success on "302 to a non-login URL" silently skips
the win. Instead define WRONG by the exact failure string (e.g. "Invalid username or
password") and treat anything else (no error, cookie set, redirect elsewhere, flag in body) as
success.

## Tooling notes

- Route all traffic through Burp (`proxies={"http":"http://127.0.0.1:8080"}`) so attempts land
  in HTTP history for triage; drive Burp via the MCP (`set_proxy_intercept_state` off) - see
  [[burp-mcp]] / `hunt-burp`.
- Keep it single-threaded when the captcha counter is per-IP (concurrent requests corrupt the
  shared "in a row" state).
- Flask session cookies are signed-but-readable (base64); decode them to confirm auth state
  (`{"logged_in":true,"username":...}`) without the secret.

## Related

- [[authentication-attacks]] (login attacks, brute force)
- [[burp-mcp]] (driving the attack through Burp)
- [[password-cracking]] (wordlist mutation when a provided list misses)
