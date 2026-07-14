---
title: "Deadends - <ENGAGEMENT>"
type: engagement-deadends
tags: [engagement, deadends, anti-loop]
date_created: <DATE>
date_updated: <DATE>
sources: []
---

# Deadends - <ENGAGEMENT>

Anti-loop record. Log a dead-end entry immediately when a path is exhausted or disproven,
not at end of session, so the same path is never re-tested. Include enough context to avoid
re-running it: timing oracle hardened, default creds rotated, endpoint 404'd, IP-blocked,
requires an account we do not have, OOB sink zero callbacks after a bounded effort, etc.

## False Positives

One line per disproven finding: `<host/finding> -- <why it is not a real finding>`.

1.

## Dead-ends

One line per exhausted/blocked path: `- [ ] <what was tried> -- <why it failed or is blocked>`.

- [ ]
