---
title: "macOS Thread Injection via Task Port"
type: technique
tags: [macos, injection, post-exploitation]
phase: post-exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## Thread injection via task port

The canonical macOS process-injection primitive when you hold a send right to another process's task port (from `task_for_pid()` with `com.apple.system-task-ports`, or the target shipping `com.apple.security.get-task-allow`, see [[macos-code-signing]]). You cannot spawn a remote thread (`thread_create_running` is blocked by mitigation), so you hijack an existing one: enumerate with `task_threads()`, `thread_suspend()` a victim thread, then read/modify its register state to build primitives.

Execution primitive: set `x0`-`x7` to your args, point `pc` at the target function, resume. To recover cleanly, register an exception handler with `thread_set_exception_ports()` and set `lr` to an invalid address (or an infinite-loop gadget as in Ian Beer's triple_fetch) so you can read the return value when the thread traps. Build a bidirectional channel by planting a send right in the remote thread's `THREAD_KERNEL_PORT` via `thread_set_special_port()`, then have the remote thread call `mach_thread_self()`/`mach_reply_port()` to hand rights back. Upgrade to arbitrary read/write with library gadgets: `property_getName()` (libobjc) reads `*x0`; `_xpc_int64_set_value(addr-0x18, val)` (libxpc) writes 8 bytes at an arbitrary address. Then map shared memory with `xpc_shmem_create()` for full R/W and multi-argument calls. The whole flow is wrapped in the `threadexec` library.

```c
// obtain the task port (needs entitlement or SIP off for Apple bins)
task_t remote;
task_for_pid(mach_task_self(), target_pid, &remote);

thread_act_array_t threads; mach_msg_type_number_t n;
task_threads(remote, &threads, &n);        // pick threads[0]
thread_suspend(threads[0]);

arm_thread_state64_t st; mach_msg_type_number_t c = ARM_THREAD_STATE64_COUNT;
thread_get_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&st, &c);
st.__x[0] = arg0; arm_thread_state64_set_pc_fptr(st, target_func);
thread_set_state(threads[0], ARM_THREAD_STATE64, (thread_state_t)&st, c);
thread_resume(threads[0]);                 // remote call fires
```

arm64e nuance: PAC signs return addresses and function pointers. Reusing existing code works (original `lr`/`pc` carry valid signatures); jumping to attacker memory requires signing the pointer inside the target, e.g. `ptr = ptrauth_sign_unauthenticated(payload, ptrauth_key_asia, 0)` before setting `pc`, or stay PAC-clean with pure gadget chains. Detection lives in EndpointSecurity: `ES_EVENT_TYPE_AUTH_GET_TASK`, `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE`, and (Sonoma) `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE`. Hardening: ship without `com.apple.security.get-task-allow` so non-root cannot grab your task port. Tooling: `threadexec`, `task_vaccine` (PAC-aware Ventura/Sonoma PoC).
