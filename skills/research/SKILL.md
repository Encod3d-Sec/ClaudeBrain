---
name: research
description: Vulnerability-research loop toward a novel CVE. Target triage -> attack-surface map -> ranked hypotheses -> investigate (RE / fuzz / audit) -> a finding deepens the loop, a dead-end pivots to a new approach. Uses the full wiki + hunt skillset. Scaffolds and persists state under raw/research/<project>/. Triggers - "research", "find a cve", "analyze this binary/library", "audit this code for vulns".
---

# Research: CVE Discovery Loop

Find and prove **one novel vulnerability** in a target (binary, library, web app/API, firmware, protocol, or source repo). The loop is persistent, resumable, and anti-loop: findings deepen it, dead-ends pivot it, and every step is driven by the knowledge base.

This skill is the research analog of the engagement framework: `raw/research/<project>/` is to research what `targets/<eng>/` is to an engagement.

---

## 0. Setup (once per target)
1. Identify target **type + version + source**. Get the code/binary: repos via WSL clone (`wsl -d kali-linux -u kali -- git clone <url> /home/kali/<name>`), releases by download.
2. Scaffold: `bash setup/new-research.sh <project_name>` -> `raw/research/<project>/{target,surface,findings,deadends,loop}.md + poc/` (also sets it active in `raw/research/active.md`, so SessionStart surfaces its status).
3. Build/run it where possible - a runnable target unlocks dynamic testing + fuzzing.
4. Fill `target.md`: what it is, version, language, build/run commands, trust boundaries.

## 1. State-first (EVERY iteration, MANDATORY)
Read `raw/research/<project>/{loop.md, deadends.md, findings.md}` before acting. Never re-run a logged dead-end without new input. Resume from the last iteration. This is the anti-loop rule - the same discipline engagements use. Run `python3 scripts/research_status.py` for the current phase + ranked next move (also auto-surfaced at SessionStart from `raw/research/active.md`).

## 2. Attack-surface map (`surface.md`)
`qmd_query` the target's tech/language/framework first, then map by type:

| Target type | First moves | Knowledge base |
|---|---|---|
| **binary / executable** | `checksec`, `strings`, RE entry + parsers, identify input handling | [[reverse-engineering]] [[ghidra]] [[radare2]] [[binary-exploitation]] [[memory-safety-bugs]] [[fuzzing]] [[aflplusplus]] [[gdb-gef]] |
| **C/C++ library** | grep dangerous APIs, build a fuzz harness, map public API | [[memory-safety-bugs]] [[fuzzing]] [[libfuzzer]] [[aflplusplus]] [[static-code-analysis]] [[semgrep]] [[codeql]] |
| **web app / API** | map routes, auth, sinks; diff vs known framework CVEs | web hunt skills (sqli/idor/auth/injection/deser/ssrf/upload) + [[source-audit-checklist]] [[static-code-analysis]] |
| **firmware** | `binwalk -Me`, extract rootfs, then treat components as binary/web | [[firmware-hardware]] [[binwalk]] |
| **protocol / network service** | RE the parser/state machine, fuzz the wire format | [[protocol-attacks]] [[fuzzing]] [[aflplusplus]] [[reverse-engineering]] [[ghidra]] |
| **source repo (any lang)** | audit + dependency CVE review + secret/history scan | [[source-audit-checklist]] [[static-code-analysis]] [[semgrep]] [[codeql]] [[trivy]] [[secret-hunting]] [[git-exposure]] + the matching vuln-class page |

Record in `surface.md`: entry points (attacker-controlled input), parsers/deserializers, dangerous sinks, privileged ops, dependencies with CVE history.

## 3. Hypothesize (ranked, in `loop.md`)
From the surface + knowledge base, write hypotheses as **`<input/location>` + `<bug class>` = `<expected primitive>`**. Rank by: reachable from an attacker boundary, attacker-controlled, lands in a dangerous sink, historically buggy area, weak/old dependency. Pick the highest-value **untested** hypothesis (skip anything in `deadends.md`).

## 4. Investigate (loop body)
Apply the matching technique + hunt skill + tool to the chosen hypothesis. Bound the effort up front (e.g. fuzz N hours / M execs; audit this component once; sweep this payload class once).
- **memory-safety:** audit sinks with [[memory-safety-bugs]], then build/point a fuzzer at the parser ([[aflplusplus]] / [[libfuzzer]], always with a sanitizer), triage crashes ([[crash-analysis]]), RE the root cause in [[ghidra]].
- **web/logic (source available):** work the [[source-audit-checklist]] (sources -> sinks), then invoke the matching `hunt-*` skill (auth/idor/injection/deser/ssrf/upload/bizlogic/smuggling) to confirm with the payload arsenal.
- **injection/parse:** malformed/oversized/encoded inputs at each parser; the relevant payload page.
- **dependency:** [[trivy]] for known-CVE deps -> prove reachability from input.

## 5. Evaluate the result
- **FINDING** (crash, leak, anomaly, logic flaw): record it in `findings.md` with class + location. **Continue looping from the finding -> go to 6. Do NOT stop at the first anomaly.**
- **NOTHING** after the bounded effort: append the approach + why-exhausted to `deadends.md`, then **go to 3 and pick a different hypothesis/approach.**

## 6. Deepen the finding (the loop continues from here)
A finding spawns its own mini-loop - each question is an iteration, and a dead-end here pivots *within* the finding before abandoning it:
1. **Root cause** - the exact flawed code/logic.
2. **Reachability** - is it triggerable from a real attacker boundary (not just an internal call)?
3. **Exploitability** - is the primitive controllable (overwrite what / leak what / which state)?
4. **Impact** - RCE / memory corruption / info leak / DoS / privesc / auth bypass.
5. **Variants** - is the same bug pattern present elsewhere (grep the codebase)?

## 7. Prove + novelty-check
- Minimal reproducible **PoC / trigger** in `poc/`.
- **Severity + CVSS**; **affected versions** (`git blame` / changelog for when introduced).
- **Novelty (decides CVE vs known):** search NVD, GitHub Security Advisories, the project changelog/issues, and `qmd_query` the wiki. Already fixed/reported -> mark `known` in `findings.md` and pivot. Genuinely new + reachable -> **candidate CVE.**

## 8. Write up (CVE-grade)
Promote the proven finding in `findings.md` (or a dedicated FIND file): title, affected versions, root cause, PoC, primitive/impact, CVSS, remediation, disclosure note. Then **feed the reusable technique/pattern back to the wiki** (`wiki/techniques/` or `wiki/payloads/`) via the `research-ingest` skill - so the next project starts ahead.

---

## Loop control (the state machine)
```
setup -> surface-map -> hypothesize -> investigate -> evaluate
   evaluate: finding  -> deepen -> prove -> writeup -> (variants? back to hypothesize)
   evaluate: nothing  -> deadend -> hypothesize (different approach)
   all hypotheses exhausted -> step back: re-map a different component (2),
                               try a new target-type angle, or note the target looks hardened.
```
- Log **every** iteration to `loop.md` as `Iter N (date): <approach> -> <result> -> <next>`. Update `findings.md` / `deadends.md` before you stop. State persists across sessions - a later session resumes the loop from `loop.md`.
- Stop conditions: a proven novel vuln (success), or all current hypotheses exhausted (record the frontier + suggested new angles).

## Output every iteration
`Iter N: <approach> -> <result> -> <next move>`, plus which files you updated. Keep the human in the loop on each pivot and each finding.
