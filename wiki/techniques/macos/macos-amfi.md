---
title: "macOS AMFI Internals"
type: technique
tags: [macos, code-signing, evasion, post-exploitation]
phase: post-exploitation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-macos]
---

## AMFI internals and dyld policy triage

AppleMobileFileIntegrity (`AMFI.kext` + userland `/usr/libexec/amfid`) is the logic behind XNU code-signature verification, entitlement checks, task-port access, and debug allowance. It registers MACF policy hooks at load; blocking its load or unload can panic. Boot-args that weaken it (SIP/secure-boot gated): `amfi_get_out_of_my_way=1` (disable AMFI), `amfi_allow_any_signature=1`, `amfi_unrestricted_task_for_pid=1`, `cs_enforcement_disable=1`. `amfid` answers the kext over Mach special port `HOST_AMFID_PORT` (18); on macOS root can no longer hijack special ports (SIP-protected, only launchd), and iOS pins amfid's CDHash.

Attacker-relevant MACF hooks: `proc_check_get_task` / `proc_check_expose_task` gate task-port access via `get-task-allow` and `task_for_pid-allow`; `file_check_library_validation` enforces platform/TeamID library validation; `proc_check_map_anon` requires `dynamic-codesigning` for `MAP_JIT`; `proc_check_run_cs_invalid` intercepts `ptrace(PT_ATTACH/PT_TRACE_ME)` and checks `get-task-allow`/`run-invalid-allow`/`run-unsigned-code`; `proc_check_mprotect` denies `VM_PROT_TRUSTED`. Crucially, recent `dyld` calls `amfi_check_dyld_policy_self()` early to decide whether `DYLD_*` vars, interposing, fallback/embedded paths, and tolerated insertion failures are allowed. So when triaging an injection surface, inspecting Mach-O load commands is not enough; you must also read the entitlements AMFI translates into dyld policy (see [[macos-code-signing]]).

```bash
BIN=/path/App.app/Contents/MacOS/binary
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
  grep -E 'get-task-allow|disable-library-validation|allow-dyld-environment-variables|allow-jit|cs.debugger|run-unsigned-code'
codesign -dvvv "$BIN" 2>&1 | grep -E 'flags=|runtime|library-validation'
kextstat | grep AppleMobileFileIntegrity   # or: kmutil showloaded | grep -i amfi
```
