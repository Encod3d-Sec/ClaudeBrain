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

## GWT debug flag routes raw server exceptions into an unescaped innerHTML sink

GWT compiles to a small number of large, obfuscated JS permutations. When a debug/verbose flag is live in production (observable from the app's own diagnostic panels leaking raw internal debug text), the compiled code branches on that boolean at the point it builds an error-display string: the production branch renders a static localized message, the debug branch concatenates the raw exception class/message/stack into an HTML string assigned via the ONE `innerHTML`-equivalent primitive the whole permutation uses (grep the file for `.innerHTML=`).

To reach the exception message, hand-craft a GWT-RPC POST body directly rather than relying on the UI: a pipe-delimited string table (`7|2|8|<base-url>|<XSRF-header-class>/<token>|<ServiceName>|<methodName>|<paramTypeClass>|<param-value>|<int-refs...>`), obtainable by copying a real request and substituting a payload into the parameter string-table slot. A server-side validation guard that echoes the rejected value back into its error message is a common, easy sink.

Confirm the sanitiser gap by grepping the same permutation for the app's own safe-HTML-escape helper name and checking it is never called on the exception-message path.

## Sources
- PayloadsAllTheThings - Google Web Toolkit

<!-- promoted-slug: a-compiled-gwt-permutation-can-ship-a-client-visible-debug-v -->
