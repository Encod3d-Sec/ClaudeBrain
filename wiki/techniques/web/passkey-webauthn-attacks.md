---
title: "Passkey and WebAuthn Attacks"
type: technique
tags: [authentication, webauthn, passkey, fido2, mfa, phishing]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [proofpoint-entra-passkey-downgrade, squarex-passkeys-pwned, thn-synced-passkey-bypass]
---

# Passkey and WebAuthn Attacks

## What it is
Passkeys are FIDO2/WebAuthn credentials that replace passwords with device-bound or synced public-key authentication. They are phishing-resistant by design because the browser binds each assertion to the relying-party origin. Passkey and WebAuthn attacks rarely break the cryptography; they target the ceremony, the fallback methods, the recovery flow, and the client-side WebAuthn API to sidestep the strong factor entirely.

## How it works
WebAuthn has two ceremonies: registration (`navigator.credentials.create`) and authentication (`navigator.credentials.get`). The browser signs a server challenge with a private key that never leaves the authenticator, scoped to the RP origin. The crypto is sound, so attackers go around it: force the user onto a weaker method (SMS, OTP, password) via downgrade or adversary-in-the-middle (AitM), abuse a permissive recovery flow, hijack the JavaScript that drives the ceremony (XSS or malicious extension), or exploit server logic that fails to bind the assertion to the session and user.

## Attack phases
Exploitation. Applies to login, MFA step-up, and account-recovery flows of any WebAuthn/passkey-enabled application.

## Prerequisites
- Target offers passkeys/WebAuthn, usually alongside one or more fallback methods.
- For downgrade/AitM: a phishing proxy or control of the network path.
- For API hijack: an XSS sink on the RP origin or a malicious browser extension.
- For recovery abuse: a recovery flow weaker than the passkey (email link, KBA, SMS).

## Methodology
1. Enumerate every authentication and step-up method the account supports; the weakest enabled method sets the real security bar.
2. Downgrade via AitM: proxy the login, spoof an unsupported or older browser/user-agent so the RP disables passkeys, and steer the user to SMS/OTP/password, which the proxy captures.
3. Client-side API hijack: via XSS or a malicious extension, break or stub `navigator.credentials.get()` (throw an error, return null) to force a password fallback, or hook `navigator.credentials.create()` during re-registration to enroll an attacker authenticator.
4. Recovery-flow abuse: trigger "lost device" and complete recovery through the weaker channel (email reset, KBA, SMS plus SIM swap) to enroll a new attacker passkey.
5. Server logic flaws: check whether the server binds the WebAuthn assertion to the authenticating user and session; test cross-account assertion replay, acceptance of user-verification flag cleared (UV=0) where UV is required, and challenge reuse.
6. Synced-passkey exposure: where passkeys sync through a cloud account (Apple, Google, Microsoft, or a password manager), compromising that account or its weaker recovery yields the passkey across devices.

## Key payloads / examples
Client-side WebAuthn API neutralisation to force a password fallback (inject via XSS or extension on the RP origin):
```javascript
// Break the passkey ceremony so the page falls back to password
navigator.credentials.get = () => Promise.reject(new DOMException('NotAllowedError'));
// Or silently hijack registration to enroll an attacker-controlled authenticator
const origCreate = navigator.credentials.create.bind(navigator.credentials);
navigator.credentials.create = async (opts) => { /* relay opts to attacker, return attacker cred */ };
```
AitM downgrade trigger (proxy rewrites the User-Agent so the RP turns passkeys off):
```
User-Agent: Mozilla/5.0 (Windows NT 10.0) AppleWebKit/605 (KHTML, like Gecko) Version/16 Safari/605
# Entra ID and some RPs disable passkey/WebAuthn for an "unsupported" UA, offering SMS/OTP instead
```
Server logic probes:
```
# replay another user's assertion against your session (broken user binding)
# submit authenticatorData with the UV flag = 0 where policy requires user verification
# reuse a previously issued challenge (missing single-use / expiry enforcement)
# present an assertion from a different origin / RP ID (missing origin check)
```

## Bypasses and variants
- SMS/OTP/password fallback is the dominant real-world bypass; phishing-resistance is only as strong as the weakest enabled method.
- Proofpoint-documented Entra ID downgrade: a phishing proxy spoofs an unsupported browser, Entra disables passkeys, and the user is steered to a weaker method (AitM policy steering).
- WebAuthn API hijack via XSS or a malicious extension to block `get()` or hijack `create()`.
- Synced passkeys: cloud-account takeover propagates the credential to attacker devices, defeating device-bound assumptions.
- Weak recovery: "I lost my device" routed to email/KBA/SMS enrolls a new passkey.

## Detection and defence
- Remove or tightly gate weak fallbacks; require an equally strong recovery (a second passkey or hardware key) rather than SMS/email.
- Enforce attestation and user verification (UV=1) where policy demands; reject UV=0 when required.
- Bind every assertion to the authenticating user and session server-side; enforce single-use, expiring challenges; reject cross-origin and cross-account assertions.
- Do not disable passkeys purely on user-agent; treat UA-based downgrade as an AitM signal.
- Protect the RP origin from XSS (strict CSP); any script on-origin can subvert the ceremony.
- For synced passkeys, harden the syncing cloud account and its recovery path.

## Tools
See [[authentication-attacks]] and [[mfa-bypass]] for the broader auth-bypass surface, [[oauth-attacks]] for federated step-up abuse, and payloads in [[webauthn-passkey]].

## Sources
- Proofpoint research (via SC Media and SecurityWeek): Entra ID passkey downgrade via AitM policy steering (slug: proofpoint-entra-passkey-downgrade).
- SquareX Labs, "Passkeys Pwned: Turning WebAuthn Against Itself" (slug: squarex-passkeys-pwned).
- The Hacker News, "How Attackers Bypass Synced Passkeys" (slug: thn-synced-passkey-bypass).
