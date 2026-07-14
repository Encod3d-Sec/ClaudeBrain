---
title: "SAML Attacks"
type: technique
tags: [authentication, exploitation, saml, sso, federation, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [payloadsallthethings-saml, epi052-saml-methodology]
---

## What it is

SAML (Security Assertion Markup Language) is the XML-based SSO standard: an Identity Provider (IdP) signs an assertion about a user, and a Service Provider (SP) trusts it. Attacks target how the SP validates that signature and processes the assertion - to forge identity, escalate privileges, or read local files. Pairs with [[oauth-attacks]] under the `hunt-federation` skill.

## How it works

SSO flow: user -> SP -> redirected to IdP -> IdP returns a signed `<Response>`/`<Assertion>` (usually base64 in a POST `SAMLResponse`) -> SP verifies the XML signature and reads `NameID` + attributes. Trust breaks when the SP verifies one element but reads another, accepts unsigned content, or fails to bind the assertion to the request/time.

## Methodology

Decode and inspect first (SAML Raider in Burp, or `base64 -d | xmllint --format -`). Then:

### Signature stripping
Some SPs accept an assertion with **no** signature (validation is skipped when the `<ds:Signature>` is absent rather than treated as a failure). Remove the `<ds:Signature>` block entirely and edit `NameID`/attributes to a target user; if accepted, full auth bypass. Test both layers: strip the **Response** signature and the **Assertion** signature independently, some SPs enforce one but not the other. Also try setting the `SignatureValue` to empty or corrupting one byte: a "signature present but never actually verified" SP fails open the same way.

### XML Signature Wrapping (XSW)
The core federation attack. Leave the original signed element in the message so the signature still validates, but add a forged copy (with your `NameID`/attributes) positioned so the SP's *processing* code reads the forged element instead of the signed one. The signature verifier and the business logic resolve a different node; the gap is the bug.

Which XSW works depends on **what the signature references**: the `<ds:Reference URI="#...">` points either at the `Response` or at the `Assertion`. XSW1/XSW2 target a **Response** signature; XSW3 through XSW8 target an **Assertion** signature. Concrete XML skeletons per position live in [[oauth-saml]] (payloads); the positions:

- **XSW1** (Response sig): duplicate the whole `Response`. The **forged Response** becomes the document root (new `ID`, your identity); the **original signed Response** is embedded inside it as a child, keeping its enveloping signature intact. Applies when the signature covers the Response.
- **XSW2** (Response sig): same as XSW1 but the signature is changed from **enveloping to detached** (moved out to a sibling position). Use when the SP rejects XSW1's enveloped layout but still resolves the outer forged Response.
- **XSW3** (Assertion sig): insert the **forged Assertion as a sibling before** the original, as the first child of `Response`. Two assertions at the same level; SPs that grab "the first Assertion" read the forged one while the signature validates the second (original).
- **XSW4** (Assertion sig): like XSW3 but the **original signed Assertion is nested as a child of the forged Assertion** instead of a sibling. Beats SPs that only look one level deep.
- **XSW5** (Assertion sig): non-standard layout, the **forged Assertion envelopes the `Signature`** (the copy wraps the signature element); the original assertion bytes are moved so the reference still resolves. Use when the signature is neither cleanly enveloped nor detached.
- **XSW6** (Assertion sig): deeper nest of XSW5, the **forged Assertion envelopes the `Signature`, which in turn envelopes the original Assertion**. Signature sits between the forged outer and original inner assertion.
- **XSW7** (Assertion sig): add a schema-lax **`<Extensions>`** element and place the **forged unsigned Assertion** inside it; the original signed Assertion stays in place. Exploits SPs that skip strict schema validation and let `Extensions` hold arbitrary children.
- **XSW8** (Assertion sig): variant of XSW7 for SPs that reject `Extensions`, use an **`<Object>`** element (from the XML-Signature schema) to hold the **original Assertion with its signature stripped**, while the forged Assertion takes the normal position.

SAML Raider automates all 8: intercept the `SAMLResponse` in Repeater, open the SAML Raider tab, pick the XSW type from the dropdown, and `Apply XSW`. If none land, the SP is resolving elements by unique `ID` (Xerces `Id`-attribute registration) or verifying over the exact consumed node; iterate through all 8 and both signature targets before concluding not-vulnerable.

### XML comment handling (NameID confusion)
A comment inside `NameID` can split parsing between the signature checker and the app, granting access to a legitimate account (the 2018 "wrapping" class affecting OneLogin/Duo/Clever and others):
```xml
<NameID>admin@target.com<!--injected-->.attacker.com</NameID>
```

### Certificate faking / key confusion
If the SP does not pin the IdP certificate, re-sign your forged assertion with your **own** key and embed your cert in `<KeyInfo>`; vulnerable SPs trust any embedded cert. SAML Raider: "Send Certificate to SAML Raider Certs" -> self-sign -> resend.

### Missing recipient / audience / replay checks
Tamper or omit `Recipient`, `Audience`, `NotOnOrAfter`, `InResponseTo`. If the SP does not validate them: cross-SP assertion reuse, indefinite **replay** of a captured assertion, or IdP-initiated injection.

### XSLT in transforms
A `<ds:Transform>` containing an XSLT stylesheet can read local files / run code during signature processing:
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="doc">
    <xsl:value-of select="unparsed-text('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### XXE
The `SAMLResponse` is XML - test classic [[xxe]] (external entity) on SPs with old parsers.

## Bypasses and variants
- **Golden SAML**: with the IdP token-signing private key (e.g. ADFS), forge assertions for any user as any IdP - persistent domain/cloud access (used in SolarWinds/SUNBURST). See [[oauth-attacks]] and the Azure AD pages.
- Encoding: deflate+base64, double-URL-encode, or swap GET/POST binding to dodge a WAF.

## Detection and defence
Verify the signature over the **exact** element you consume; reject unsigned/multiple assertions; pin the IdP certificate; validate `Recipient`/`Audience`/`InResponseTo`/`NotOnOrAfter`; disable DTD/external entities and XSLT; schema-validate; short assertion lifetimes + one-time use.

## Tools
**SAML Raider** (Burp - XSW + cert faking, the main tool), `xmlsec1`, `xmllint`, manual base64/deflate. Federation context: [[oauth-attacks]], [[authentication-attacks]], [[jwt-attacks]]. Driven by the `hunt-federation` skill.

## Sources
- PayloadsAllTheThings - SAML Injection
- epi052 - "How to Hunt Bugs in SAML; a Methodology" (XSW1-XSW8 taxonomy, SAML Raider) (slug: epi052-saml-methodology).
- Somorovsky et al., "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012) - original XSW research.
