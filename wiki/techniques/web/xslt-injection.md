---
title: "XSLT Server-Side Injection"
type: technique
tags: [xslt, ssrf, lfi, rce, injection, web]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-web]
---

# XSLT Server-Side Injection (SSRFi / LFI / RCE)

If an application applies an attacker-controlled XSL stylesheet server-side (document converters,
report/PDF generators, ESI-style transforms), the stylesheet grammar itself yields file read, SSRF,
port scan, file write, and often RCE. Key insight: hardening the input-XML parser does NOT harden
the stylesheet parser. If classic XXE payloads fail, fingerprint the processor first, then switch
to processor-specific primitives instead of retrying generic XXE.

## Fingerprint then map
Fingerprint with `system-property('xsl:vendor')` / `xsl:version` to identify libxslt (GNOME/lxml),
Saxon, Xalan (Apache), or .NET/MSXML. Post-fingerprint map:
- libxslt/lxml/PHP: `document()`, `exsl:document` (write), `php:function()` (RCE).
- Saxon: `unparsed-text()` (arbitrary text-file read), `xsl:result-document`, reflexive Java
  extension functions (needs `ALLOW_EXTERNAL_FUNCTIONS`).
- Xalan/Apache: Java extension namespace `xmlns:rt="...xalan/java/java.lang.Runtime"` blind exec.
- .NET Framework: `msxsl:script` C# (needs `XsltSettings.EnableScript`); unsupported on .NET Core.

## Notes
On libxslt, `document('/etc/passwd')` often errors (parsed as XML), so a failed passwd read
does NOT prove the processor is hardened; prefer `unparsed-text()`. Treat Java/boolean-only returns
as blind RCE and pivot to DNS/HTTP callbacks, file writes, or time delays. When writing files
through XML this is XML encoding (use `&amp;` for a literal `&`, not `%26`).

Wordlist: carlospolop/Auto_Wordlists xslt.txt. Payload strings: [[xslt]] (payloads).
Related: [[xxe]], [[wiki/techniques/web/ssrf]].

## Sources
- HackTricks (pentesting-web)
