# Auto-Triggers: what fires automatically, and when

What the framework fires on its own, so you know what activates for a given task.

**Core principle:** auto-triggers **inject context** (a suggestion the model reads and acts on, or a warning). They do **not** silently run commands. Every fire is a visible injected line. Nothing executes a tool by itself.

**Source of truth** (edit these, not this doc, to change behaviour):
- keyword -> skill: `skills/hunt/triggers.json`
- tech fingerprint -> tests: `scripts/playbook.json`
- hook logic: `skills/hooks/*.py`
- hook registration (per device): `setup/install-hooks.sh` -> `~/.claude/settings.json`

This page is a snapshot; regenerate the tables from those files if they change.

---

## What fires, and when

| Event | Hook(s) | What happens |
|---|---|---|
| **SessionStart** | `session-start.sh`, `engagement-init.py` | Loads `session/hot.md`; injects the active-engagement summary + top next-moves + recent log + wiki-health line (only if broken) + active research status (`research_status.py`); regenerates `index.md` if stale; self-heals the engagement file set. |
| **UserPromptSubmit** | `hunt-trigger.py` | Keyword-matches the prompt against `triggers.json` (code-stripped, intent-gated): a hard hit surfaces the relevant **Skill(x)** to load (routing; the skill carries the mandate), a surface hit a softer "consider Skill(x)". Leak-safe telemetry to `.trigger-fire.jsonl`. |
| **PreToolUse (Bash)** | `scope-guard.py` | scope / RoE advisory (deterministic safety guard). |
| **PreToolUse (Write)** | `session-guard.py` | Warns when a write would put a client marker into a generic `session/*` file. |
| **PostToolUse (Bash)** | `recon-capture.py` | Fingerprint auto-route (to the hunt Skill) + OOB callback correlation + a once-per-engagement GATE-1 wiki-first nudge (exploit-shaped command while `killchain.md` Weaponize is undone). A framework-meta guard suppresses false fires. Advisory. |
| **PreCompact** | `pre-compact.sh` | Reminds to persist state (`gsd:pause-work`) before context compacts. |

All 7 hooks inject context, route to a skill, or fire a deterministic safety guard; none prescribes methodology, blocks the model, or silently runs a tool, and all fail open. Canonical set: `scripts/check-hooks.py` `EXPECTED_HOOKS`.

---

## 2. What you TYPE -> hunt / workflow skill

Prompt contains the keyword (case-insensitive) -> that skill is suggested. Multiple can fire at once.

| Keywords | Skill |
|---|---|
| ssrf, server-side request forgery | hunt-ssrf |
| xss, cross-site scripting | hunt-xss |
| prototype pollution, dom clobbering | hunt-xss |
| sqli, sql injection | hunt-sqli |
| idor, broken access control, access control | hunt-idor |
| rce, command injection, remote code execution | hunt-rce |
| auth bypass, account takeover, ato | hunt-auth |
| csrf, cross-site request forgery | hunt-auth |
| oauth, saml, sso, federation | hunt-federation |
| graphql, xxe, ssti | hunt-injection |
| active directory, kerberoast, as-rep, dcsync, adcs, bloodhound, golden/silver ticket, pass-the-hash, ntds, esc[0-9], ntlm relay | hunt-ad |
| aws, s3 bucket, gcp, imds, metadata service, 169.254.169.254, iam privesc, ec2, service account key, cloud credential | hunt-cloud |
| m365, entra, azure ad, exchange online | hunt-m365 |
| fortigate, pulse secure, cisco vpn, palo alto, vpn appliance | hunt-vpn |
| deserialization, ysoserial, gadget chain, pickle, viewstate, marshal.load, phpggc | hunt-deserialization |
| request smuggling, http smuggling, cl.te, te.cl, desync, h2c smuggling | hunt-smuggling |
| file upload, unrestricted upload, upload (web)shell, malicious file upload, zip slip | hunt-upload |
| business logic, workflow bypass, price manipulation, coupon abuse, mass assignment, parameter tampering | hunt-bizlogic |
| web cache poisoning, cache deception, unkeyed input/header | hunt-cache |
| ctf challenge, crackme, capture the flag, pwn this/challenge, reverse this binary, solve this challenge, stego | ctf-category (routes to crypto/rev/forensics/stego/pwn) |
| research ingest, wiki ingest, ingest this cve/writeup/advisory/blog/url/repo, add to wiki | research-ingest |
| find a cve, vuln research, analyze this binary/library/firmware, audit this code, 0day | research (CVE-discovery loop; scaffolds raw/research/&lt;project&gt;/) |
| prompt injection, jailbreak, llm attack, excessive agency, indirect prompt | hunt-llm |
| api security/testing, bola, bfla, swagger/openapi, grpc | hunt-api |
| n-day, patch diff, bindiff, silent patch, 1-day | nday |
| disclose, request a cve, report to vendor, coordinated disclosure, security.txt | disclosure (finding -> CVE) |
| what next, next move, where to focus, prioritize, what should I attack/test | next-move |
| ingest, synthesize findings/recon/output, process recon | ingest |
| coverage, what haven't we tested, test gaps, are we thorough, untested | coverage |

52 triggers total (42 vuln-type + 10 attack-surface). xxe/ssti/graphql route to hunt-injection (no separate skills). azure ad -> hunt-m365 (not hunt-cloud) by design. (Counts drift as `triggers.json` grows; recount with `python3 -c "import json;d=json.load(open('skills/hunt/triggers.json'));print(len(d['triggers']),len(d['surface_triggers']))"`.)

---

## 3. What you RUN -> command-time triggers

### Before the command: scope/RoE advisory (`scope-guard.py`, PreToolUse)
**Advisory only - never blocks.** Injects `SCOPE/RoE ADVISORY ...` when the command:
- targets an out-of-scope host/IP (CIDR-aware: `10.0.3.9` caught by out-of-scope `10.0.3.0/24`), or
- uses RoE-forbidden tooling given `scope.md` flags: `no_bruteforce` (hydra/medusa/kerbrute/...), `no_dos` (slowloris/--min-rate huge/nmap -T5/...), `passive_only` (any active scanner).

Fails open: a missing scope entry = no warning, never a block. No active engagement = silent.

### After a bash command: fingerprint router + OOB correlation + GATE-1 nudge (`recon-capture.py`, PostToolUse)

**Fingerprint auto-route** - scans the command + its output for tech and injects the hunt skill to fire. A framework-meta guard suppresses false fires when the command reads/edits the vault's own playbook/hook/wiring machinery (its output is full of playbook tokens). Detected tech (from `playbook.json`):

```
graphql  spring  supabase  wordpress  laravel  next.js  firebase  magento
jenkins  tomcat  gitlab  elasticsearch  influxdb  redis  mssql  jwt  oauth  s3
azure  fortigate  kubernetes  docker  swagger  ldap  smb  x-cache  mongodb
confluence  drupal  joomla  grafana  phpmyadmin  weblogic  iis  struts  jira
llm  mcp  github actions  grpc  exchange  ivanti  moveit  sharepoint  activemq
coldfusion  php-cgi  vcenter  screenconnect  papercut  ofbiz
```
(80 fingerprints. Each emits the hunt skill to load, e.g. `jenkins detected -> load Skill(hunt-rce)`. The tech list above is an illustrative subset; regenerate from `playbook.json`.)

**OOB callback correlation** - flips a waiting `oob.md` row to HIT when its planted token appears in the command + output blob (operator polling OAST/Collaborator), so a confirmed blind-bug callback is surfaced immediately instead of being missed.

**GATE-1 wiki-first nudge** - the only enforcement the kill-chain board's GATE lines get. When an exploit-shaped command runs (`sqlmap`/`hydra`/`medusa`/`msfconsole`/`evil-winrm`/`nxc ... -x`/a reverse shell, incl. inside a vm.sh/ssh/wsl wrapper) while the active `killchain.md` `## 2. Weaponize` section has no `[~]`/`[x]` progress, it nudges once per engagement to query the wiki + pick the payload + mark the Weaponize item BEFORE hand-rolling. Fire-once (`.gate1-nudged` marker), framework-meta exempt, advisory + fail-open.

Tools whose output is fingerprinted (matched at command position, including inside `vm.sh`/`ssh`/`wsl` bridge wrappers): `nmap masscan nxc netexec crackmapexec ffuf httpx subfinder rustscan naabu dnsx katana gau amass gowitness arjun nuclei gobuster feroxbuster curl wget whatweb wpscan nikto nslookup dig sqlmap dalfox swaks`. (Capturing results into `state.md`/`loot.md` is now state-first discipline, not a hook nudge.)

---

## By task - concrete examples

| You do | Auto-fires |
|---|---|
| type "test login.x.com for sql injection" | hunt-sqli (wiki query + payloads) |
| run `nmap -sV host` -> output shows Jenkins + GraphQL | router: jenkins + graphql detected -> load hunt-rce / hunt-injection |
| run `hydra ...` with `no_bruteforce: true` in scope | scope-guard advisory warning (before run) |
| run `nmap 10.0.3.9` where `10.0.3.0/24` is out of scope | scope-guard advisory warning |
| type "solve this crackme" | ctf-category -> reverse-engineering page + radare2/pwntools |
| type "what next" | next-move (ranked moves) |
| start a session on an engagement | engagement-init: state + top-3 next moves + wiki health |

---

## How you know it fired

Every trigger prints a visible line the model then acts on:
- `MANDATORY ... load Skill(<skill>)` (hard keyword hit) / `consider Skill(<skill>)` (surface hit)
- `Fingerprint auto-route (playbook.json) ...` (a recon command found tech)
- `SCOPE/RoE ADVISORY ...` (command hit scope/RoE)
- `=== Engagement state ===` (session start)

Nothing runs a command on its own. To change what fires: edit `triggers.json` (keywords), `playbook.json` (fingerprints + tests), or the hook `.py` files; re-run `bash setup/install-hooks.sh` only when adding a new hook event.
