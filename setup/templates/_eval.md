---
title: "Agent Eval - {{ENGAGEMENT}}"
type: engagement-eval
tags: [engagement, eval, agent-metrics, retrospective]
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
---

# Agent Eval

Close-out assessment of how the AGENT (not the target) performed, to steer harness improvement.
Two halves:
- **Hard numbers = the `## Metrics (auto)` block** (skill/hook/tool counts, drift signals, tokens,
  start->finish time). NOT hand-typed - `Skill(learn)` Phase 0d runs `scripts/eval_metrics.py <eng>
  --write` to fill it from the hook telemetry (`.events.jsonl`) + the session transcript. The agent
  cannot self-measure tokens/time; the transcript is ground truth.
- **Judgement = the sections below** (what the numbers can't say): WHY drift happened, what went right,
  scores. Filled by the agent at close-out.

## Time allocation (judgement of the split, ~100% total; the auto block has the real totals)
| bucket | share | what it was |
|--------|-------|-------------|
| productive (toward the flag) | | |
| research / wiki lookups | | |
| dead-ends (exhausted vectors) | | cross-ref Deadends.md |
| drift (off-intended-path / rework) | | the avoidable part |

## Drift moments (the avoidable time sinks)
<!-- One line each: what I did, why it was drift, the one-line fix. These feed harness-retro.md. -->
-

## What went right (keep doing)
-

## Score
- efficiency (1-5):
- followed-intended-path (1-5):
- capture-discipline (1-5):
- one thing to change next box:
