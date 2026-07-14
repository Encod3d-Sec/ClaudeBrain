---
title: "Account Takeover (ATO)"
type: technique
tags: [account-takeover, authentication, oauth, jwt, exploitation, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-accounttakeover]
---

# Account Takeover

## What it is

Gaining unauthorized full control of another user's account. ATO is the *outcome*; the routes run through password reset, registration/identity logic, OAuth/SSO, and chained web bugs. The highest-value web finding class. Overlaps [[authentication-attacks]], [[oauth-attacks]], [[jwt-attacks]]; driven by the `hunt-auth` skill.

## Password reset attacks
- **Reset poisoning:** inject `Host` / `X-Forwarded-Host` so the reset email link points to your domain -> victim clicks -> token leaks (`https://attacker/reset?token=...`).
- **Token leak via Referer:** a 3rd-party link on the reset page leaks the token in `Referer` to the external site.
- **Email parameter pollution / CC:** send the token to you while resetting the victim:
```text
email=victim@x.com&email=attacker@x.com
{"email":["victim@x.com","attacker@x.com"]}
email=victim@x.com%0d%0acc:attacker@x.com
email=victim@x.com,attacker@x.com
```
- **Weak tokens:** guessable (timestamp/userID/sequential), no expiry, reusable, or returned in the API JSON response.
- **Username collision:** register `"admin "` (trailing space); reset for the padded name but the backend trims and resets the real `admin` (CVE-2020-7245, CTFd).
- **Unicode normalization:** register `demⓞ@gmail.com`; if normalized to `demo@gmail.com` after the uniqueness check, your reset hits the victim.
- **Host-of-trust / no current-password:** change-email / change-password endpoints that do not require the current password or a fresh session.

## Registration & identity logic
- **Pre-account-takeover:** register the victim's email (unverified) before they sign up; when they later sign in via OAuth, accounts merge under your password.
- **Email change without re-verification**; **response manipulation** (change `"success":false`->`true`, or strip an MFA step).

## ATO via chained web bugs
- **XSS** -> steal session / add attacker email ([[xss]]).
- **CSRF** -> change-email/password form ([[csrf]]).
- **Request smuggling** -> capture another user's request/session ([[http-request-smuggling]]).
- **JWT** -> edit `sub`/`email`, `alg:none`, weak-secret crack ([[jwt-attacks]]).
- **IDOR** on `/account/{id}` update endpoints ([[access-control]]).
- **OAuth** redirect_uri/`state` bugs -> steal the code ([[oauth-attacks]]).

## Real-world
Reset poisoning, OAuth pre-ATO, and "change email without current password" are recurring high-bounty HackerOne reports. CVE-2020-7245 (CTFd username collision) is the canonical normalization case.

## Detection and defence
Single-use, short-lived, high-entropy reset tokens bound to the user; never trust `Host` for email links (use a fixed canonical base URL); require current password + re-auth for email/password/MFA changes; verify email before merge/login; normalize+canonicalize identifiers **before** uniqueness checks; set `Referrer-Policy: no-referrer` on sensitive pages.

## Tools
Burp ([[burp-suite]]) + Collaborator, `nuclei` reset/takeover templates. Driven by the `hunt-auth` skill.

## Sources
- PayloadsAllTheThings - Account Takeover
