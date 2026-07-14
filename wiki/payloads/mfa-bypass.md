---
title: "Payloads: MFA / 2FA Bypass"
type: payloads
tags: [payloads, mfa, 2fa, authentication, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: MFA / 2FA Bypass

Defeat the second factor (OWASP A07). Routed via the `hunt-auth` skill. See [[mfa-bypass]]; reset/login [[account-takeover]].

## Skip / state
```
complete step 1 (password) -> go DIRECTLY to the post-MFA endpoint (forced browsing)
the pre-MFA session cookie is already authenticated -> use it on protected pages
response manipulation: {"mfa_required":true} -> false ; {"verified":false} -> true ; 4xx -> 200
remove the otp/mfa param entirely; send empty otp=
toggle a 2fa-enabled flag in a profile/update request
```

## OTP brute / reuse
```
no rate limit: brute 000000-999999 (Turbo Intruder / ffuf)
weak code: 4-digit, sequential, predictable seed/time
reuse: one OTP works multiple times / does not expire
race the verify (parallel) to dodge lockout (see race-conditions)
OTP leaked in response JSON / sent to attacker-controlled email (param pollution)
```

## Backup / alternate factor
```
backup codes guessable / unlimited tries
"remember this device" cookie reusable / forgeable / no binding
downgrade: SMS/email fallback to a weaker or attacker-controlled channel
recovery flow bypasses MFA entirely (reset password -> logged in, no 2FA)
disable 2FA without re-auth (CSRF/IDOR on the disable endpoint)
```

## SSO / token
```
direct OAuth/JWT login path skips MFA (see oauth-saml, jwt)
"trusted" SAML assertion sets MFA-satisfied claim -> forge it
```

## Real-world
Forced-browse-past-MFA, OTP brute without lockout, and reset-password-skips-2FA are the recurring ATO bypasses; "remember device" cookies and response-flag tampering are close behind.
