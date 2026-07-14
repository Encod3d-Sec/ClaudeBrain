---
name: walkthrough
description: Auto-assemble a report-ready walkthrough.md for a SOLVED engagement - render staged evidence synchronously, populate the Evidence gallery, and draft the step-by-step reproduction from state/loot/paths/log.md without fabricating. Use when asked to "write the walkthrough", "assemble the walkthrough", "close out the box/engagement", or fired automatically by the loop-driver Stop-hook once an engagement is marked SOLVED and its walkthrough is stale.
---

# Walkthrough auto-assembly

Turn a solved engagement into the full, report-ready `targets/<eng>/walkthrough.md`: rendered
evidence, a populated `## Evidence` gallery, and a drafted narrative, so the operator only
reviews/polishes instead of assembling from scratch.

## Convention: mark close-out explicitly

At close-out, write a STATUS heading into `state.md`:
```
## STATUS: SOLVED
```
(`OWNED` / `ROOTED` / `COMPLETE` also count.) This is the signal the loop-driver Stop-hook
watches for -- once present, it nudges `Skill(walkthrough)` on every Stop until the walkthrough
is actually assembled (self-clears the moment it is complete).

## Steps

### (a) Render all staged evidence SYNCHRONOUSLY and verify
Do NOT rely on the flaky detached auto-drain. Run the loop-driver drain in the FOREGROUND for
every area that has staged cards, then confirm the PNGs actually landed on disk:
```bash
python3 skills/hooks/loop-driver.py --drain "$(pwd)/targets/<eng>" recon
python3 skills/hooks/loop-driver.py --drain "$(pwd)/targets/<eng>" poc/leads
python3 skills/hooks/loop-driver.py --drain "$(pwd)/targets/<eng>" poc/pages
python3 skills/hooks/loop-driver.py --drain-tmux "$(pwd)/targets/<eng>"
ls targets/<eng>/**/*.png targets/<eng>/poc/**/*.png targets/<eng>/poc/**/**/*.png 2>/dev/null
```
The drain retries + verifies on-disk before clearing a staged card, so this foreground run is
the reliable path (this is the step that would have caught a walkthrough shipping empty).

### (b) Scaffold + gallery
```bash
python3 scripts/build-walkthrough.py <eng>
```
Idempotent: scaffolds the walkthrough structure from the framework template if missing, and
populates the `## Evidence` gallery from every rendered card on disk. Never clobbers existing
narrative -- safe to re-run after step (a).

### (c) Draft the narrative -- never fabricate
Read `state.md`, `loot.md`, `paths.md`, and `log.md` for the active engagement, and write the
step-by-step reproduction into the non-Evidence sections (Access -> Recon -> Foothold ->
Privilege escalation -> root/flag), using the EXACT commands, creds, and per-step results already
captured in those files. If a fact needed for a section is not present in the state files, do NOT
invent it -- leave a clearly marked `_TODO: <what is missing>_` for the operator instead.

### (d) Preserve exploit scripts
Copy any exploit script (payload, escape/forge script, webshell) into
`targets/<eng>/poc/scripts/`, the same thm_tricipher discipline `ctf-box` and `screenshot` use --
the reviewer needs the code and the state together, not just a screenshot.

### (e) Verify complete
Before finishing, confirm:
- no unfilled template markers remain (`<entrypoint>`, `<foothold`, or a bare `- target:` /
  `- reach:` stub line), and
- the `## Evidence` gallery has at least one rendered image reference row.

If either check fails, go back and fill the gap (more evidence to drain, more narrative to draft)
rather than leaving the walkthrough half-done.

## Scope and safety
All output stays under `targets/<eng>/` (gitignored) -- never write client data into `session/*`
or `wiki/`. Every step here is best-effort: `build-walkthrough.py` is idempotent and no-clobber,
the drain is bounded and fails open (a card that still won't render stays staged for a later
attempt, not a blocker). Real client engagements still go through `Skill(evidence)` for redaction
before the walkthrough ships in a report; CTF/lab work can skip that.

## On demand (not just the Stop-hook)
This skill is not only auto-fired. Invoke it directly whenever you are ready to write the
walkthrough, assemble the walkthrough, or close out the box/engagement -- the same five steps
apply whether triggered by the nudge or asked for explicitly.
