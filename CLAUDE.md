# Pentesting & Bug Bounty Wiki: Schema

---

## Quick reference

| Operation | Action |
|---|---|
| Query | `qmd_query "..."` via `wiki-search` MCP -> read results -> synthesise |
| Ingest skip check | Read frontmatter only; skip page if ingest slug already in `sources:` |
| Re-index / wiki status | `wiki` skill |
| Git clone | Always WSL: `wsl -d kali-linux -u kali -- git clone <url> /home/kali/<name>` |
| Run tooling against a target | Kali VM over SSH: `bash /root/vm.sh '<cmd>'` (VPN route + tools + chromium live there) -> `docs/virtual-machine.md` |

---

## Skills and tools

| Task                                          | Use                                                                                    |
| --------------------------------------------- | -------------------------------------------------------------------------------------- |
| Multi-step planning                           | `superpowers:brainstorming` then `superpowers:writing-plans`                           |
| Execute a plan                                | `superpowers:subagent-driven-development`                                              |
| Debug unexpected behavior                     | `superpowers:systematic-debugging`                                                     |
| About to claim done                           | `superpowers:verification-before-completion`                                           |
| Write/edit vault `.md`                        | `obsidian:obsidian-markdown`                                                           |
| Fetch URL for ingest                          | `WebFetch` tool                                                                        |
| Read vault file                               | `Read` tool with machine path (see below)                                              |
| Search vault                                  | `qmd_query` (semantic) or `qmd_search` (keyword) via `wiki-search` MCP                 |
| Maintain wiki index (re-index, status)        | `wiki` skill                                                                           |
| Load engagement playbook / FIND schema        | Read `targets/TARGETS.md`                                                              |
| Audit CLAUDE.md (full review)                 | `claude-md-management:claude-md-improver`                                              |
| Update CLAUDE.md (targeted session learnings) | `claude-md-management:revise-claude-md`                                                |
| Session end / pause work                      | `gsd:pause-work` (optional plugin) or the manual pause-work steps                                                                       |
| Parallel independent tasks                    | `superpowers:dispatching-parallel-agents`                                              |
| About to attack a web endpoint                | `hunt-<type>` skill (see auto-triggers below)                                            |
| Driving a web target through Burp (proxy-history triage, Repeater/Intruder/Collaborator) | `hunt-burp` skill (Burp MCP; setup [[burp-mcp]])              |
| Starting recon on any target                  | wiki-recon skill                                                                       |
| Validating / moving finding to Completed      | triage then evidence skills                                                            |
| Vuln/CVE research on a target (binary/repo/app/firmware) | `research` skill (scaffolds `raw/research/<project>/`)                       |

Vault-local skills (read file directly from `skills/`): `code-review/`, `obsidian/`, `wiki/`, `research/` (CVE-discovery loop), `disclosure/` (finding -> CVE). Workflow + hunt skills live under `skills/hunt/`: all `hunt-*` plus `wiki-arsenal` (fast PARALLEL wiki lookup engine over techniques/payloads/tools/cheatsheets; `arsenal` delegates to it), `triage`, `evidence`, `coverage`, `ingest`, `next-move`, `wiki-recon`, `nday`, `research-ingest`, `ctf-box`, `ctf-category`, `screenshot` (visual PoC capture via `scripts/shot.py`/`capture.sh`, chromium on Kali -> `targets/<eng>/poc/`), `screenshot-burp` (Burp Repeater request/response PoC via `scripts/capture.sh burp`), and `learn` (post-engagement knowledge harvest: diff a completed engagement against the wiki, promote the delta via the leak-gated stage->promote pipeline). The `claude-md-improver/` local copy is an offline fallback (auto-invocation disabled); prefer the `claude-md-management:claude-md-improver` plugin. For MCP setup, hooks, and plugin troubleshooting: read `skills/skills-setup.md`.

Search rule: never read `wiki/index.md` to find pages - always search first. MCP tool names: `mcp__wiki-search__qmd_query` (semantic), `mcp__wiki-search__qmd_search` (keyword).

`session/memory.md` holds long-term editorial patterns. Load it when making editorial or tagging decisions.

---

## Hunt Skill Auto-Triggers

Vuln-type triggers are fired deterministically by the `hunt-trigger.py` UserPromptSubmit hook, which matches the prompt against `skills/hunt/triggers.json` (single source of truth) in two tiers: `triggers` (explicit vuln-type terms -> a **MANDATORY** `Skill(<hunt>)` load-first directive) and `surface_triggers` (natural attack-surface terms like "login form"/"upload field"/"api endpoint" -> a softer "consider `Skill(...)`" line). When a hard trigger fires, treat the directive as a real instruction: load the named hunt skill before responding, unless it is genuinely irrelevant (then say why in one line). Edit `triggers.json` to change mappings, not this table. Every prompt (fire or miss) is logged leak-safe to `.trigger-fire.jsonl` (no prompt text); run `python3 scripts/trigger-stats.py` to see match rate and tune the surface tier. The table below is the human reference plus the non-keyword rows (triage/evidence) that stay model-judged.

Vuln-type rows (SSRF/XSS/SQLi/IDOR/RCE/auth/federation/injection/m365/vpn -> matching hunt skill) live in `triggers.json`, fired by the hook. Only the model-judged rows remain here:

| Condition | Skill |
|-----------|-------|
| Starting recon on target (subdomains, endpoints, surface) | wiki-recon |
| "Is this valid?", "should I report?", finding needs confirmation | triage |
| Moving finding Research -> Completed | triage then evidence |

---

## Engagement discipline (state-first, anti-loop)

**Execution loop (per offensive step, ALWAYS).** The hooks below are advisory and can misfire or go
silent (e.g. when the `wiki-search` MCP drops); THIS loop is the real enforcement because it is always
in context. On every engagement, run each step in order, do not skip under momentum:
0. **Board-first.** Open `targets/<eng>/killchain.md` (the wiki-wired kill-chain board: Recon ->
   Weaponize -> Deliver -> Exploit). Work the current phase's open items (`[ ]`/`[~]`) in order; mark
   each `[x]` as it lands. Honor the three GATE lines, which map onto the steps below: GATE 1 = no
   hand-rolled exploit before its wiki item is `[x]` (step 1); GATE 2 = no exploit step goes `[x]`
   without a `poc/` image (step 3); GATE 3 = an exhausted vector is marked `[!]` + one `Deadends.md`
   line, then move to the next open item, never re-run `[!]` (step 5's stop condition).
1. **Wiki-first.** Before exploiting a fingerprinted service/class, consult the wiki for it -
   fastest path is `Skill(wiki-arsenal)` (parallel lookup across techniques/payloads/tools/cheatsheets;
   say "deep" for the 4-agent synthesized card), or directly `qmd_query`/`qmd_search` via the
   `wiki-search` OR `caveman-shrink` MCP (same index), or `Read` the `wiki/` page.
   MCP-independent: if the MCP is down (it has dropped mid-session on multiple engagements), run
   `bash scripts/wiki-query.sh "<tech> exploit"` (semantic; `-k` for an exact CVE/tool string) - it
   wraps the SAME qmd index. If one path is down, use another; NEVER degrade to ad-hoc grep or skip it.
2. **Tools, not hand-rolls.** Reach for the installed tool (nmap/ffuf/nuclei/httpx/nxc/sqlmap/borg/...),
   never a hand-rolled `curl`/`/dev/tcp` loop; if none fits, say why in one line. Enumerate NON-STANDARD
   installed tools (borg/borgmatic/restic/duplicity, backup + secret managers) as a loot/privesc lead -
   a leaked backup passphrase + a reused key beats grinding a hardened-container escape.
3. **Capture the request AND each landing, live.** `capture.sh req` the real request+response for every
   exploit/lead request, and screenshot each success to `poc/` the moment
   it lands (`capture.sh ev` / `capture.sh tmux` / `shot.py`), never at the end. Evidence is captured
   live now (no auto-card staging). NEVER hand-write / fabricate an evidence card.
4. **Persist immediately.** A host/cred/path/flag lands -> write `state.md`/`loot.md`/`paths.md` before
   the next move; a dead-end -> one `Deadends.md` line.
5. **Close out.** Both flags captured -> set `## STATUS: SOLVED` in state.md AT ONCE, then run
   `Skill(walkthrough)`, then `Skill(learn)` (harvest this box's generic lessons into `wiki/`). Set
   SOLVED promptly so the close-out sequence runs.

Token control and real findings come from the same rule: do not repeat work.

- **Scope-first.** Read `targets/<eng>/scope.md` before acting. Never touch an out-of-scope target or use forbidden tooling (`no_bruteforce`/`no_dos`/`passive_only` flags). The `next-move` analyzer already filters out-of-scope hosts and suppresses spray/active probing per RoE; respect the same bounds in everything else.
- **State-first.** Before any recon, spray, or exploit attempt, read the active engagement `state.md`, `loot.md`, `paths.md`, and `Deadends.md`. Never re-run a documented dead-end or re-spray a known-failed cred without new input (new cred, new pivot, new payload class).
- **Stop condition.** A vector is exhausted after a bounded effort (e.g. OOB sink: ~30-40 payloads zero callbacks; spray: full user x pass matrix once). On exhaustion: append one line to `Deadends.md` + update `paths.md` status, then switch vector. Do not grind, do not re-loop.
- **Capture as you go.** After a recon/cred tool runs, extract results into `state.md`/`loot.md` immediately (state-first discipline: capture the moment a tool returns). Prose in chat is lost; tables persist across sessions and devices.
- **Tooling-first.** Use the installed tool (nmap/ffuf/nuclei/nxc/linpeas), not a hand-rolled bash reimplementation - better output, fires the fingerprint router, and `recon-capture.py` snaps it to evidence. Hand-rolled bash only when no tool fits (say why). Enforced by the `ctf-box` + `hunt-*` skills, not a runtime hook.
- **OOB-gate blind bugs.** Blind SSRF/SSTI/SQLi claims need an out-of-band callback, never inference. Enforced per hunt skill.
- **Reuse loot.** Reuse captured creds across `state.md` hosts before researching new ones. Default/known creds first (look up vendor defaults via context7, see [[default-credentials]]); broad spraying of captured creds is a last resort, not an early or auto move.
- **Distill reusable knowledge.** When an engagement yields a default cred or a reusable API request pattern, add the **generic** form (product + cred / endpoint + impact, no client specifics) to `wiki/cheatsheets/default-credentials.md` or `api-request-findings.md`. Next engagement, check these first. Client specifics stay in `targets/<eng>/`. At close-out, `Skill(learn)` sweeps the whole completed engagement for any generic lesson still missing from `wiki/` and promotes the delta through the leak-gated stage (`wiki-stage.py`) -> promote (`wiki-promote.py`) pipeline; run it once the engagement is `SOLVED` and its walkthrough is assembled.

---

## Behavior hooks

Caveman plugin installed. SessionStart hook activates full mode automatically - respond terse, drop articles/filler, fragments OK. If hooks fail, activate manually: `/caveman`.

SessionStart also auto-loads `session/hot.md`. No manual reads needed.

Engagement-state hooks (live via `~/.claude/vault-hooks` symlink -> `skills/hooks/`). All fail open (any error -> allow, never trap). Policy: **deterministic guards ENFORCE (deny the tool call); semantic reflexes ADVISE (inject a suggestion).** Enforcement is reserved for no-judgement checks (scope/RoE/output-hygiene) where blocking the wrong action costs zero tokens; judgement calls (wiki-first, tools-not-manual, intended-path) stay advisory because a false block wastes more time than it saves. Escape hatch for a bad block: `touch skills/hooks/.enforce-off`. Full mechanics in `docs/auto-triggers.md`; the behaviorally-relevant summary:

| Hook | Event | Effect |
|------|-------|--------|
| `engagement-init.py` | SessionStart | Self-heals the engagement file set; injects state summary + top next-moves + session cache + OOB HITs + drift/CVE warnings. |
| `hunt-trigger.py` | UserPromptSubmit | Routes to hunt skills from `triggers.json` (surfaces the relevant Skill; the skill carries the mandate); leak-safe telemetry to `.trigger-fire.jsonl`. Skips injected/non-prompt content. |
| `recon-capture.py` | PostToolUse/Bash | Routes detected tech -> the hunt Skill (`playbook.json`), auto-correlates OOB callbacks (waiting -> HIT), and fires a once-per-engagement GATE-1 wiki-first nudge when an exploit-shaped command runs while `killchain.md` Weaponize is undone. Framework-meta guard suppresses false fires. Advisory. |
| `scope-guard.py` | PreToolUse/Bash | ENFORCES (denies the command) on out-of-scope host/IP (CIDR-aware), RoE-forbidden tooling, or an `echo "=== ==="` output-banner. Fail-open; `.enforce-off` marker downgrades to advisory. |
| `session-guard.py` | PreToolUse/Write | Warns when a write would put a client marker into a generic `session/*` file. Advisory, never blocks. |

Register/repair the set per-device with `bash setup/install-hooks.sh`; `engagement-init` warns at SessionStart if a hook is unregistered (canonical set in `scripts/check-hooks.py`).

Active engagement set by `targets/active.md`. Create one with `bash setup/new-engagement.sh <name> <pentest|bugbounty|ctf>`. Per-type schema from `setup/templates/<type>/`; `engagement_type` in state.md frontmatter drives analyzer + self-heal. Files: `targets/<eng>/{state,loot,paths,killchain,log,scope,walkthrough,eval,Vuln-index,Deadends,oob}.md` + `ingest/` + `poc/` (curated exploit/PoC/flag shots) (all self-healed by `engagement-init`). `eval.md` = per-engagement AGENT self-assessment (tokens/time/drift estimates), filled at close-out by `Skill(learn)`. `killchain.md` = the wiki-wired kill-chain board (phase checklist + `### 4a` coverage table + the three GATE lines). `walkthrough.md` = full copy-pasteable boot-to-root reproduction (distinct from the terse `log.md` audit); `log.md` doubles as the per-engagement continuity cache (its newest block is surfaced at SessionStart, so client narrative goes there, never in generic `session/hot.md`). Missing wiki pages surfaced by `scripts/wiki-gaps.py`.

Framework subsystems (each is a script + an on-demand skill; detail in `docs/auto-triggers.md`):

| Subsystem | Entry point | Key rule |
|-----------|-------------|----------|
| Ingest | `ingest` skill | Drop raw output in `targets/<eng>/ingest/`; the skill synthesizes -> state/loot/paths then archives. |
| Next-move | `scripts/next_move.py` / `next-move` | Ranks moves (type + scope aware). Update tables after acting so the next run re-ranks. |
| Fingerprint testing | `scripts/playbook.json` | Maps tech -> targeted tests + hunt skill + the `wiki/payloads/` arsenal. Extend both as you learn new tech. |
| Coverage | `killchain.md` 4a table / `coverage` skill | Per-asset untested classes live in the kill-chain board's `### 4a` table. Add a row with status `[x]` + a `poc/` image when you test a class, or the gap recurs (`next_move.py` surfaces `[gap]` moves). |
| Finding quality | `scripts/find-lint.py` | Findings scaffold from `setup/templates/_find.md`; run find-lint before /evidence and before a report. |

**Client-data boundary (hard rule):** all client/engagement specifics (hosts, IPs, creds, domains, findings, narrative) live ONLY under `targets/<eng>/` (git-ignored). Never write them into `session/*`, `wiki/`, tracked `docs/`, scripts, or commit messages; per-engagement narrative goes to `targets/<eng>/log.md` (audit + continuity cache). `session-guard.py` advises on violations; run `bash scripts/check-leaks.sh` before sharing. Full detail: `docs/sharing.md`.

---

## Machine-specific vault access

Per-machine hostnames and vault paths live in the git-ignored `CLAUDE.local.md`
(copy `CLAUDE.local.example.md` to create it), kept out of the published repo.
The path resolvers (`setup/vault-path.sh`) and hooks self-locate or read
`OBSIDIAN_VAULT` / `QMD_VAULT`, so a single-machine setup needs no local file.

@CLAUDE.local.md

---

## Directory structure

```
ClaudeBrain/
├── CLAUDE.md                    <- this file  (+ README.md, LICENSE)
├── targets/                     <- engagements (PRIVATE; client data only here, git-ignored)
│   ├── active.md                <- pointer: current engagement dir name
│   ├── scrub-terms.txt          <- private leak-check extras (not shipped)
│   └── <eng>/                   <- self-healed set (state,loot,paths,killchain,log,scope,walkthrough,eval,oob,hot,Vuln-index,Deadends) + ingest/ + poc/ (curated PoC shots) + Vulns/ (pentest)
├── wiki/
│   ├── index.md                 <- catalog of all wiki pages
│   ├── moc.md                   <- graph map-of-content (domain hubs; navigate here)
│   ├── overview.md              <- methodology map and coverage status
│   ├── techniques/              <- active-directory, cloud, web, osint, cracking, network,
│   │                              red-team, linux, exploit-dev, methodology, mobile-iot
│   ├── payloads/                <- per-vuln-class payload arsenal (hunt skills pull from here)
│   ├── tools/                   <- per-tool reference pages
│   ├── cheatsheets/             <- quick-reference command sheets
│   └── courses/  CTF/           <- course notes; challenge writeups
├── session/
│   ├── hot.md                   <- rolling 3-entry summary (auto-loaded at startup)
│   ├── log.md                   <- append-only audit trail
│   └── memory.md                <- long-term editorial patterns
├── docs/
│   ├── workflows.md             <- step-by-step workflow guide
│   ├── page-types.md            <- required sections per page type
│   ├── setup.md                 <- machine setup and path config
│   ├── virtual-machine.md       <- Kali attack VM + vm.sh SSH bridge; when/how to run tooling vs. targets
│   ├── sharing.md               <- client-data boundary; how to share safely
│   ├── conventions.md           <- cross-referencing, log format, style guide
│   └── auto-triggers.md         <- what auto-fires (hooks, triggers.json, playbook) and when
├── scripts/                     <- automation (self-documenting via docstrings): next_move,
│                                   status.py (on-demand engagement dashboard: phase/counts/evidence/deadends/moves),
│                                   wiki-query.sh (qmd CLI wiki-first fallback when the MCP drops),
│                                   find-lint, lint-wiki, lint-md-tables.py (GFM table integrity), gen_index, build_moc, cve_feed, freshness,
│                                   check-hooks, check-leaks.sh, trigger-stats, wordlist-* (+wordlists/),
│                                   shot.py, capture.sh (one entrypoint, modes: ev=live cmd+url card / req=curl
│                                   request-response / tmux=real tmux-session card / burp=Burp Repeater PoC), vm-scan.sh, burp-mcp-cli.py,
│                                   build-walkthrough.py (scaffold + auto-populate the walkthrough Evidence gallery),
│                                   playbook.json; archive/ = old migrations
├── setup/                       <- bootstrap.sh, install-hooks.sh (per-device hook reg), install-skills.sh, new-engagement.sh, new-research.sh, templates/<type>/ + templates/research/
├── tests/                       <- pytest suite for engagement + wiki automation (205 tests)
├── skills/                      <- code-review/ obsidian/ wiki/ research/ disclosure/
│   │                               claude-md-improver/ (offline fallback) + hooks/ (hook scripts)
│   └── hunt/                    <- all hunt-* + triage/evidence/coverage/ingest/next-move/
│                                   wiki-recon/nday/research-ingest/ctf-box/ctf-category/screenshot/screenshot-burp/learn + triggers.json
└── raw/
    ├── research/                <- CVE writeups/blogs/advisories + active research projects (<project>/ from new-research.sh; the research skill writes loop state here)
    ├── assets/                  <- screenshots and other non-text files (read-only)
    └── git/                     <- cloned repos (WSL path, not Windows mount)
```

**Rules:**
- `raw/` is read-only. Exceptions: populate `raw/git/` via git clone (WSL only), and `raw/research/<project>/` research workspaces created by `setup/new-research.sh` (the `research` skill writes loop state there). Research on public targets is not client data; client/engagement work still lives only under `targets/`.
- `wiki/` and `targets/` are fully owned by Claude. Create, update, and cross-reference freely.
- `wiki/index.md` and `session/log.md` updated after every ingest, query-that-produces-a-page, and lint pass (framework work only; client/engagement narrative goes to `targets/<eng>/log.md`).
- Update `CLAUDE.md` when vault structure changes; `docs/setup.md` for machine/path changes; `docs/conventions.md` for editorial standards changes.

Read `targets/TARGETS.md` for the engagement playbook: FIND naming, severity definitions, directory structure, and the wiki integration rule.

**Session end:** Before closing any session, run pause-work (`gsd:pause-work` if the gsd plugin is installed on this machine, else do the steps manually). Generic/framework summary -> `session/hot.md`, `session/log.md`, `session/memory.md` (no client specifics). Client/engagement narrative -> `targets/<eng>/log.md` (audit + continuity cache) ONLY.

---

## Page types and frontmatter

Full schema in `docs/page-types.md`. **Skip rule:** during ingest, read only the frontmatter first. If the ingest slug is already in `sources:`, skip the page entirely. Only read full content when you will update it.

---

## Wiki Workflows

Read `docs/workflows.md` before performing any ingest, target session, lint, or query. When a technique appears in multiple sources, synthesise all into one technique page; do not create one page per source.

---

## Output rules

- Never use em-dashes (`--`). Use a comma, semicolon, or rewrite the sentence. (`--` is permitted inside code blocks as a CLI flag.)
- Never use emojis.
- Do not narrate what you are doing with echo/printf inside commands (label banners, "now doing X" lines, `=== ... ===` / `== x ==` / `-- x --` separators). You already explain each step in your normal response text, so echoing it into the command is duplicate noise, and the harness already shows every command with its own output. Run commands directly.
- **Concrete values, not shell variables, in target commands.** The operator watches the live terminal, so write commands a human would type: real IPs/URLs/paths inline (`curl -s http://10.1.1.5:8080/api`), not `T=http://...; curl "$T/api"` or `$VAR` placeholders. Reserve variables for genuinely repeated long secrets (a captured token/cookie). walkthrough.md is already var-free; hold live commands to the same bar.
- **Send interesting requests to Burp, not just curl.** When you confirm or want to probe a noteworthy request (SSRF, LFI, SQLi/injection, a deser payload, an auth bypass), push it into **Burp Repeater** via `Skill(hunt-burp)` / the Burp MCP (or `scripts/capture.sh burp` for a PoC) so the operator can replay and inspect it manually. curl is fine for quick loops; the load-bearing exploit requests belong in Repeater for operator visibility.
- Never add a `Co-Authored-By` trailer, a "Generated with Claude Code" line, or any similar attribution footer to git commit messages or PR bodies. (Overrides the harness default that appends one.)

---

## Image handling

Never copy image embeds (`![[Pasted image *.png]]` or `![](url)`) into wiki pages. Reconstruct commands as code blocks from context. Wiki pages must be image-free.
