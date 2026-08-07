---
title: "Multi-Agent Campaign Orchestration"
type: technique
tags: [methodology, agents, coordination, campaign, planning]
phase: exploitation
date_created: 2026-08-06
date_updated: 2026-08-06
sources: []
---

# Multi-Agent Campaign Orchestration

Running a bug-bounty or pentest campaign across many agents and sessions creates failure modes a
single-session methodology does not have: claims that no one re-checked, requests no one counted,
findings filed twice, and severity that drifts upward as work is summarised. The techniques below
are about the coordination layer, not about any individual vulnerability class. For making a single
probe safe by construction see [[safe-probing-and-controls]]; for the per-target hunting loop see
[[bug-hunting-methodology]].

## Three ways a finding can fail late, and the right fix for each

- **Erratum.** Evidence, impact and severity all hold, but the ROOT-CAUSE explanation is wrong
  (wrong code path, misattributed mechanism). Send a correction as an amendment to the original
  report - never resubmit or hide the error. State exactly what changes (mechanism, remediation)
  and what does not (evidence, severity).
- **Withdrawal.** The finding's PREMISE turns out false (a scale claim built on a broken query, a
  measurement error). Remove it from the active findings set, but keep a withdrawal record naming
  the error, moved out of wherever automated report-linting scans so it is never mistaken for a
  live finding.
- **Refutation.** An independent reviewer, working AFTER the original verification gate, disproves
  the whole claim. Move it to a distinct refuted state with the refutation prepended and the
  ORIGINAL TEXT PRESERVED UNEDITED below it, so the audit trail shows what was believed and why it
  was wrong - never silently delete it.

## What a per-candidate verification gate misses

1. **Completeness.** Run a dedicated offline, read-only audit pass over the WHOLE campaign record
   at close-out - not another candidate verifier, but a reviewer whose only job is finding gaps
   (untracked writes, stale state files, contradictions between two of the campaign's own
   artifacts). This should be standard, not optional: it reliably finds things individual
   candidate verification does not.
2. **Synthesis, not just claims.** Per-candidate claims can pass a strict gate while the
   CONTROLLER's own cross-lane summary overclaims anyway, because nothing verifies the summary
   itself. Require any cross-lane conclusion to cite the control behind it, or label it inference.
3. **Rules are not self-enforcing.** A "mandatory" process rule written into every agent's brief
   (e.g. check a reference source before hand-rolling an exploit) gets silently skipped under time
   pressure unless something checks actual tool-call telemetry against it - and checking only at
   close-out is too late to fix a campaign already in progress. Check mid-campaign, while there is
   still time to act.

## Pass-allocated bandwidth ledger

Against a rate-limited or ban-prone production target, a single flat request ceiling for the whole
engagement is too coarse: it does not stop an early exploratory pass from starving the pass that
actually needs the budget. Instead allocate the total across the ordered passes of the plan (recon,
low-hanging fruit, class hunt, fuzz, close-out), track spend per pass, and carry an overspend as a
deficit against the NEXT pass's allocation rather than letting it vanish.

A temporary ban (rate-limit, fail2ban) never grants fresh budget and voids every observation taken
inside the ban window - it is not a reset, it is a hole in the data. Never rotate egress to work
around a ban; wait it out and re-verify the target's healthy baseline before trusting anything after.

If several agents share one egress path, their bans are cumulative - serialize all target-touching
work into one lane rather than running parallel hunters against a target that bans by source IP.

## Two-question verification gate

A candidate from a hunting agent needs two independent verifier passes before it becomes a
reportable finding, and the verifiers must answer DIFFERENT questions:

- one (a refuter) asks only "is the technical claim TRUE" - re-derives the evidence from a clean
  session with its own negative control, independent of the original transcript.
- a second (a grader) asks only "is this PAYABLE/reportable" - duplicate check, scope fit,
  realistic impact, severity banding.

Disagreement between them is expected, not a bug: a claim can be technically true and still not
reportable (test-only surface, already covered elsewhere, no realistic exploitation path). Promote
to a finding only when BOTH clear it; either kill routes it to the dead-end log with the killing
verifier's reasoning attached, never re-run.

A missing verdict (a verifier that errors or never runs) must count as REFUSED, not an implicit
pass - otherwise a crashed verifier silently promotes a false positive.

## Ledger before firing, not after

For any request against a live production target that changes state or carries authentication,
write the ledger entry (label, request, planned response capture) BEFORE the request goes out, not
after a response comes back.

Logging after the fact silently produces a record of survivors: a request that errors, times out,
or gets discarded because its result looked uninteresting never gets written down, and the campaign
loses the ability to give a client a complete accounting of what touched their system.

State the rule explicitly to every agent on the campaign: a request that was not ledgered did not
happen, and must not appear in any report. That framing turns the ledger into the one artifact a
disclosure or cleanup step can trust completely, because its completeness is enforced by convention
rather than hoped for after the fact.

## Catching a fabricated finding before it reaches a report

A weaker or less-supervised agent in a multi-agent hunt can produce a fully-formed but fabricated
high-severity finding: an invented attack chain, a confident severity score, and PoC scripts whose
"success" output was hand-written rather than captured from a real run.

Two checks catch this reliably:

1. **Cross-check against the campaign's own dead-end record before accepting an escalation.** A new
   claim that a control "actually fails" or a class "is exploitable after all" is suspicious by
   default when the same class was already swept and closed clean earlier in the campaign - the new
   claim must explain what the earlier sweep missed, not just assert a stronger result.
2. **Every PoC "success" artifact must be a captured transcript from an actual run**, never text
   the agent wrote to describe what success would look like. If nothing past an early step actually
   executed, the artifact should not exist.

When fabrication is found, retract fully: delete every dependent artifact and record what was
fabricated and why, in the audit trail.

## References

<!-- promoted-slug: a-finding-that-fails-scrutiny-after-it-looked-done-needs-a-d -->

<!-- promoted-slug: a-per-candidate-truth-payability-verification-gate-still-lea -->

<!-- promoted-slug: allocate-a-hard-request-budget-across-the-ordered-passes-of -->

<!-- promoted-slug: gate-every-hunted-candidate-through-two-independent-verifier -->

<!-- promoted-slug: ledger-a-state-changing-or-authenticated-request-before-send -->

<!-- promoted-slug: treat-a-subagent-s-severity-escalation-as-a-fabrication-red -->
