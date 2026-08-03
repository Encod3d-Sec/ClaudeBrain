---
title: "Google Web Toolkit (GWT) Attacks"
type: technique
tags: [gwt, deserialization, rpc, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings]
---

# Google Web Toolkit (GWT)

## What it is

GWT compiles Java into obfuscated JavaScript front ends that talk to the server over **GWT-RPC**, a custom Java serialization protocol. The attack surface is hidden behind obfuscation: enumerate the RPC methods, decode the wire format, then attack the Java backend - most impactfully via Java **deserialization**. Related: [[insecure-deserialization]], [[reverse-engineering]].

## How it works
The app bootstraps from `*.nocache.js`, which references per-permutation `*.cache.js` and `*.gwt.rpc` serialization-policy files. Each RPC request is a pipe-delimited string encoding the service interface, method, parameter types, and a string table. Because parameters are Java objects deserialized server-side, GWT-RPC endpoints are prime deserialization and type-tampering targets.

## Methodology
1. **Map the surface:** GWTMap parses the bootstrap to recover service interfaces, methods, and parameter types from the obfuscated code + `.gwt.rpc` policies.
```bash
gwtmap.py -u http://TARGET/app/app.nocache.js --backup            # enumerate services/methods
gwtmap.py -u http://TARGET/app/app.nocache.js --filter AuthenticationService.login --rpc --probe
```
2. **Decode/replay RPC:** use the GDS toolset (Burp) to decode requests into readable method+params, then tamper.
3. **Attack the backend:**
   - **Deserialization:** parameters are deserialized Java objects - if the classpath has a gadget (Commons-Collections, etc.), craft a chain for RCE; see [[insecure-deserialization]] and the `hunt-deserialization` skill.
   - **Authorization (BFLA):** call methods the UI never exposes (admin services discovered by GWTMap) as a low-priv user.
   - **Parameter tampering / IDOR:** swap object IDs and types in the decoded RPC.
   - **EL / injection:** values flow into server logic - test SQLi/EL/command injection on the decoded parameters.

## Tools
- `FSecureLABS/GWTMap` - recover and probe the GWT-RPC attack surface from `*.nocache.js`.
- `GDSSecurity/GWT-Penetration-Testing-Toolset` - Burp plugin to intercept + decode GWT-RPC.
- Deserialization payloads: `ysoserial` ([[insecure-deserialization]]).

## Detection and defence
Enforce authorization on every RPC method (not just the UI); avoid native Java deserialization of untrusted input (use allowlists / safe formats); keep gadget-prone libraries off the classpath; validate parameter types server-side. Obfuscation is not a control - GWTMap defeats it.

## Sources
- PayloadsAllTheThings - Google Web Toolkit
