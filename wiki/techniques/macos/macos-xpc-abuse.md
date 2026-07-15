---
title: "macOS XPC Abuse"
type: technique
tags: [macos, xpc, privilege-escalation]
phase: privilege-escalation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## XPC abuse: audit_token spoofing and PID reuse

XPC's one-to-one connection abstraction sits on Mach ports, which are single-receiver but multiple-sender. That mismatch breaks per-message authorization when a privileged daemon checks the caller with the wrong API. Two distinct bugs.

audit_token spoofing (CVE-2023-32405, Sector7): `xpc_connection_get_audit_token` returns the token from the most-recently-received message. If service A performs an authorization check outside its event handler (e.g. inside a `dispatch_async` block) or while parsing a reply, a second sender can overwrite the token mid-check. Variant 1: connect to privileged-but-reachable service B (runs as root, e.g. `diagnosticd`) and to target A (e.g. `smd`); duplicate A's client-port send right and hand it to B so B's replies land on A. Ask B to monitor a process (floods A with messages/sec) while you spam A with the privileged request (`SMJobBless` route 1004). When the race hits, A sees B's audit token during `connection_is_authorized` and installs your privileged helper as root. Variant 2 hijacks a reply port: capture A's pending reply send-once right, forward it to B, and let B's reply overwrite the token while your forbidden request is parsed. Apple's fix was per-service (`xpc_dictionary_get_audit_token`, which reads the token from the specific Mach message), so the bug class persists in unaudited services.

```c
// Variant 1 core: reuse A's client send right as B's client port
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
// craft B's connect packet using a_client instead of a fresh port
```

Hunt it with a Frida hook that flags calls outside the delivery path:

```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
  onEnter(a) {
    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
    if (!bt.includes('_xpc_connection_mach_event'))
      console.log('[!] audit_token fetched outside handler\n' + bt);
  }
});
```

PID reuse: when a service authorizes by PID (`processIdentifier` / `xpc_connection_get_pid` in `shouldAcceptNewConnection`) instead of audit token, send the malicious message, then immediately `posix_spawn()` the allowed binary so it inherits the PID before the check runs. Fork a flood of senders each racing a `posix_spawn` of the authorized binary. Static tell: `shouldAcceptNewConnection` calling `processIdentifier` and never `auditToken`.
