---
title: "MFA Bypass"
type: technique
tags: [authentication, exploitation, mfa, portswigger, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [ps-general-concepts, ps-indepth-attacks, ps-labs-auth, thm-adv-mfa]
---

## What it is

MFA (Multi-Factor Authentication) bypass techniques defeat or circumvent second-factor verification to gain access using only the first factor — typically a stolen or guessed password — or by abusing flaws in how the second-factor step is enforced.

## How it works

Two-factor authentication adds a second verification step (something you have — a TOTP code, SMS code, or physical token) after the password. Bypass is possible when the application:

- Does not enforce the second step server-side before granting an authenticated session
- Uses a weak or guessable second factor (short numeric codes without brute-force protection)
- Ties second-factor validation to a cookie that can be controlled by an attacker
- Uses SMS as the delivery channel (vulnerable to SIM swapping and interception)

True 2FA requires two different factors. Verifying the same factor twice (e.g., password + email code) is just single-factor authentication with an extra step — the knowledge factor is simply checked twice.

## Prerequisites

- Valid first-factor credentials (username + password) for the target account
- For logic bypass: knowledge of post-login URL structure
- For cookie manipulation: attacker has their own valid account to observe the flow
- For code brute force: no rate limiting or lockout on the 2FA endpoint

## Methodology

### 1. Simple Step Skip (Logic Bypass)

After completing the first login step (password), the user lands on a 2FA prompt page. Test whether the application has already granted session access before the second factor is submitted:

1. Log in with valid credentials (or the victim's credentials if obtained)
2. When redirected to the 2FA prompt, manually navigate directly to an authenticated page:

```
https://target.com/my-account
https://target.com/dashboard
```

If the application loads the authenticated page without requiring code entry, the 2FA step is enforced only client-side (or not at all server-side).

### 2. Broken Logic: Account Cookie Manipulation

Observe the multi-step login HTTP sequence. If a cookie is set after step 1 that identifies the account being verified:

```http
POST /login-steps/first HTTP/1.1
username=carlos&password=qwerty

HTTP/1.1 200 OK
Set-Cookie: account=carlos
```

And the second step validates the code against that cookie value:

```http
POST /login-steps/second HTTP/1.1
Cookie: account=carlos
verification-code=123456
```

Attack: log in with your own account to obtain a valid session, then change the `account` cookie to the victim's username before submitting the 2FA code:

```http
POST /login-steps/second HTTP/1.1
Cookie: account=victim-user
verification-code=§000000§
```

Then brute-force the 4–6 digit code with Burp Intruder. This grants access to the victim's account without knowing their password.

**Intruder setup for numeric brute force:**
- Attack type: Sniper
- Payload type: Numbers
- Range: 000000 to 999999, step 1
- Format: minimum 6 digits (zero-padded)
- Look for a `302` redirect in the response status

### 3. Brute Force 2FA Code

Even without cookie manipulation, if there is no lockout on the 2FA endpoint, brute-force the code directly:

```http
POST /login/mfa HTTP/1.1
Cookie: session=YOUR_SESSION
mfa-code=§0000§
```

For 4-digit codes: 10,000 combinations. For 6-digit TOTP: 1,000,000 combinations (but valid only for ~30 seconds, so requires high speed or a rate-limit-free endpoint).

If the application logs the user out after N failed 2FA attempts, automate the full login-plus-2FA sequence using Burp Turbo Intruder or a macro that replays the first-step login before each code attempt.

### 4. SIM Swapping (Conceptual)

SMS-based 2FA delivers the code via text message. SIM swapping involves socially engineering the target's mobile carrier to transfer the victim's phone number to a SIM card controlled by the attacker. Once successful, all SMS messages — including 2FA codes — are received by the attacker.

This is an out-of-band social engineering attack, not a technical web exploit, but is relevant when assessing SMS-based 2FA risk.

### 5. Cookie / Token Reuse

If the second-factor verification sets a persistent cookie or token indicating "MFA completed," test whether this token can be:

- Reused from a previous session without repeating MFA
- Forged by modifying a user-controlled claim (see [[jwt-attacks]] for JWT-based tokens)
- Replayed across different accounts if the MFA token is not bound to a specific user identity

### 6. Account Recovery Bypass

Password reset and account recovery flows often bypass MFA entirely. If the recovery flow resets credentials without requiring MFA verification, it provides a path to account takeover that circumvents the second factor. Test:

- Password reset via email link: does resetting the password also reset or bypass MFA?
- Admin-triggered password reset: does this session receive MFA exemption?
- Backup codes: can they be brute-forced? Are they single-use?

## Key Payloads / Examples

Step-skip test — navigate after step 1 completion:

```
# After entering correct password on step 1, before entering code:
GET /my-account HTTP/1.1
Host: target.com
Cookie: session=<session_after_step_1>
```

Cookie manipulation for account takeover:

```http
POST /login2 HTTP/1.1
Cookie: account=victim-user; session=YOUR_OWN_SESSION
Content-Type: application/x-www-form-urlencoded

mfa-code=§000000§
```

Intruder numeric payload — 6-digit zero-padded:

```
Payload type: Numbers
From: 0  To: 999999  Step: 1
Min integer digits: 6  Max: 6
Min fraction digits: 0
```

## Bypasses and Variants

| Bypass Method | Root Cause |
|---|---|
| Direct URL navigation | Server grants session state after step 1 without enforcing step 2 |
| Account cookie manipulation | Second-factor step uses attacker-controllable cookie to identify account |
| Code brute force | No lockout or rate limiting on 2FA endpoint |
| SIM swap | SMS used as second factor; phone carrier is social-engineered |
| MFA token reuse | Completed-MFA token not bound to session, user, or expiry |
| Recovery flow bypass | Account recovery resets state without requiring second factor |
| Email-based 2FA | Code delivered to email — same knowledge factor effectively verified twice |

## Detection and Defence

- Enforce the 2FA step server-side — do not grant session access until both factors are verified
- Bind the 2FA verification to the specific session and user — do not use user-controlled cookies to determine which account is being verified
- Apply rate limiting and lockout to 2FA code submission endpoints
- Use app-based TOTP (Google Authenticator, Authy) rather than SMS
- Ensure completed-MFA tokens are cryptographically bound to the user and session
- Invalidate all sessions on password reset; require re-authentication including 2FA
- Make backup codes single-use and rate-limit their consumption

## Tools

- [[burp-suite]] — Intruder for 6-digit code brute force; Turbo Intruder for multi-step automation
- [[burp-suite]] Macros — automate login step 1 before each 2FA brute-force attempt

## Sources

- PortSwigger Academy: Authentication Vulnerabilities — Vulnerabilities in Multi-Factor Authentication
- PortSwigger Lab 6: 2FA simple bypass
- PortSwigger Lab 7: 2FA broken logic
- TryHackMe: Multifactor Authentications room
