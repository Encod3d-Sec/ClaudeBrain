---
name: next-move
description: Ranked next offensive moves from engagement state. Reads state/loot/paths, runs the deterministic analyzer, elaborates the top move. Use when asked "what next", "where to focus", "prioritize", or at the start of an engagement session.
---

# Next Move

Turns the passive engagement-state tables into a ranked, actionable plan.

## Run the analyzer (deterministic, cheap)
```
python3 scripts/next_move.py        # top 5
python3 scripts/next_move.py -v     # full list
```
Reads the active engagement (`targets/active.md` -> `targets/<eng>/{state,loot,paths}.md`).
Output tags:
- `[now]` open path or usable-cred action, do it this session
- `[test]` a tech fingerprint matched (playbook.json) - targeted tests + the hunt skill to load; severity-ranked (pre-auth criticals score highest)
- `[acquire]` reachable host with no creds yet, go get a foothold/cred
- `[blocked]` path stalled, the line shows the blocker and what unblocks it

## Model re-rank (optional, when asked to prioritize)
The analyzer score is a deterministic ANCHOR, not the last word - it is blind to cross-row chaining, exploitability, and bug-bounty depth. When the user explicitly asks to prioritize (not at SessionStart), pull the structured candidates and re-rank with judgment:
```
python3 scripts/next_move.py --json    # [{score, tag, text}, ...]
```
Read the JSON + `targets/<eng>/log.md` (recent narrative) + open FINDs in `Vuln-index.md`, then produce a final top-3. You MAY override the deterministic order, but ONLY with a one-line stated reason (e.g. "chains into the open SSRF path", "this cred likely reused on the DC"). Keep the deterministic score visible next to each so the override stays auditable. Do not invent moves not grounded in the state tables.

## Then (model, token-light)
1. Read the top item. Confirm it is still valid against `state.md`/`loot.md` (cred not since rotated, host still reachable).
2. Elaborate ONLY the top 1-2 moves: concrete next command or skill to invoke (e.g. a `hunt-*` skill, an nxc spray, a config dump). One to two lines each. Do not restate the whole list.
3. If the top move maps to a hunt skill (SSRF, relay, MSSQL, etc.), invoke that skill.

## Discipline
- Do not suggest `[blocked]` work as if actionable; surface what unblocks it instead.
- Never re-suggest a known-failed cred x host (the analyzer already filters `reused-where`); if you find one slipping through, the loot/paths table is stale, fix it.
- After acting, update `state.md`/`loot.md`/`paths.md` so the next run re-ranks correctly. The loop only stays sharp if results flow back.
