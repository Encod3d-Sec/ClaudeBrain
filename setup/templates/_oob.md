---
title: "OOB ledger: {{ENGAGEMENT}}"
type: engagement-oob
engagement: "{{ENGAGEMENT}}"
date_created: "{{DATE}}"
date_updated: "{{DATE}}"
---

# OOB callback ledger: {{ENGAGEMENT}}

One row per planted out-of-band payload. Creating the row at PLANT time is the
blind-bug confirmation gate: the recon-capture hook auto-flips `status` to `HIT`
when a callback label lands in a command's output, and SessionStart surfaces
HITs. Never claim a blind finding (SSRF/RCE/SSTI/XXE/deser) without a HIT row.

`status`: waiting (planted, no callback yet) | HIT (callback received) | expired | actioned (FIND scaffolded)

| token | sink | class | planted | status | source |
|-------|------|-------|---------|--------|--------|
