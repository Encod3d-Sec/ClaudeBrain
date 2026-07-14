---
name: hunt-bizlogic
description: Business-logic flaw hunting - workflow/state bypass, price/quantity tampering, negative/overflow values, coupon/refund abuse, mass assignment, and logic races. The top-paying bug class with no scanner coverage. Wiki-first, FIND schema output.
---

# Hunt: Business Logic

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "business logic flaw workflow bypass" via wiki-search MCP -> read matching page.
```
Core page: [[business-logic]]. Overlaps [[access-control]] (IDOR), [[race-conditions]] (logic races), mass assignment. Payload arsenal: `wiki/payloads/race-conditions.md`.

**Self-heal:** wiki query empty -> create stub `wiki/techniques/web/business-logic.md` before proceeding.

## Scope Check
- Confirm in scope. **Logic bugs are app-specific: map the intended workflow first** (read the feature, the happy path, every state transition). Read `Deadends.md`.

## Approach (no scanner finds these)
Find an assumption the developer made and break it: that steps happen in order, that values are positive, that the client can't change a field, that an action can't be repeated.

## Methodology
1. **Map the flow:** enumerate every step and state of the target feature (checkout, transfer, signup, KYC, password reset, subscription). Note each parameter and which server checks it.
2. **Step/state bypass:** skip a step (go straight to the final endpoint), replay an earlier step, do steps out of order, reuse a one-time token, access step N without completing N-1.
3. **Value tampering:**
```
quantity = -1            # negative -> credit / refund
price / amount = 0.01    # client-supplied price
currency swap            # pay in weaker currency, credited in stronger
integer overflow / very large qty
decimal/rounding (0.001 * 1000)
```
4. **Repetition / limits:** apply a coupon N times, redeem a gift card twice, or exceed a per-account limit via parallel requests (logic [[race-conditions]] - test concurrency).
5. **Mass assignment / parameter injection:** add fields the UI never sends (`isAdmin`, `role`, `balance`, `verified`, `discount`, `userId`) to JSON/form bodies; observe privilege/state change.
6. **Trust-boundary confusion:** values the server should compute but trusts from the client (total, tax, role, KYC status, account tier); flags re-sent and re-trusted on a later request.
7. **Identity/authorization logic:** action allowed for the wrong account state (unverified user performs verified-only action), or for another user's object (-> [[access-control]] / hunt-idor).
8. **Distill to wiki (when confirmed):** if the finding is a reusable logic-abuse pattern, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/business-logic.md` (or `--kind api-pattern --target-page cheatsheets/api-request-findings.md` for a reusable request pattern). Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed (demonstrate the unintended favorable outcome):
```
Create Vulns/Research/FIND-XXX-<SEV>-logic-<feature>-<host>.md
Add row to Vuln-index.md: | FIND-XXX | price tamper -> free order | host | CONFIRMED |
```
Severity: by impact - CRITICAL = direct financial theft / auth bypass / unlimited privilege; HIGH = discount/refund abuse, quota bypass with money impact; MEDIUM = limited abuse, needs preconditions.

Exhausted (server recomputes all values, enforces state machine, ignores extra fields, idempotency keys present):
```
Append to Deadends.md: - [ ] logic <feature> -- server-side price/state authoritative; mass-assign ignored; idempotent
```

Report: Status + files created.
