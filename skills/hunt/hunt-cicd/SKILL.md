---
name: hunt-cicd
description: CI/CD pipeline attack hunting (GitHub Actions focus) - pwn requests (pull_request_target), script injection, self-hosted runner takeover, cache poisoning, OIDC-to-cloud token theft, poisoned pipeline execution. Wiki-first, FIND schema output.
---

# Hunt: CI/CD Pipeline Attacks

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "GitHub Actions pwn request CI/CD" via wiki-search MCP -> read cicd-github-actions if found.
```
Apply documented pwn-request, cache-poisoning, OIDC-theft, and PPE techniques + payloads/cicd.

**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/cloud/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm the repo/org/pipeline is in scope. RoE note: opening PRs against third-party repos may be out of scope; do not test unauthorised orgs.
- Read Deadends.md - skip paths already marked exhausted

## Attack Surface Signals
- Public repos with `.github/workflows`; `pull_request_target` / `workflow_run` triggers
- Untrusted `${{ github.event.* }}` interpolated into `run:` steps
- Self-hosted runner labels; `permissions: id-token: write` (OIDC to cloud)

## Methodology
1. Enumerate workflows + triggers (gato/Gato-X, octoscan, poutine).
2. Pwn request: a `pull_request_target` workflow that checks out the fork HEAD and holds secrets -> fork, inject a build step, open a PR, exfil `env`/secrets/`GITHUB_TOKEN`.
3. Script injection: `a"; <cmd>; #` in a `github.event.*` value interpolated into a `run` step.
4. Self-hosted runner: non-ephemeral = persistence between jobs + cross-repo on a shared pool.
5. Cache poisoning: a fork job writes an `actions/cache` entry that a trusted base job restores.
6. OIDC theft: pull `ACTIONS_ID_TOKEN_REQUEST_TOKEN`/`URL`, assume the cloud role off-box; check trust-policy `sub` scoping.
7. PPE: modify a `Makefile`/`package.json` the pipeline runs (bypasses CODEOWNERS on workflow files).
8. Confirm: secret/token exfil to your endpoint, or successful cloud-role assumption.
9. **Distill to wiki (when confirmed):** if the finding is a reusable pwn-request, OIDC-theft, or PPE technique, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/cicd-github-actions.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output

If finding confirmed (secret/token exfil or cloud-role assumption proven):
```
Create Vulns/Research/FIND-XXX-SEVERITY-cicd-<repo>.md
Add row to Vuln-index.md: | FIND-XXX | CI/CD <issue> on <repo> | <repo> | PARTIAL |
Include the vulnerable workflow and the proof (exfil or role assumption).
Severity: CRITICAL if OIDC-to-cloud role assumption or GITHUB_TOKEN/secret exfil; HIGH if pwn-request/script injection RCE on runner; MEDIUM if cache poisoning with limited reach
```

If path exhausted:
```
Append to Deadends.md: - [ ] CI/CD attack on <repo> -- no exfil/role assumption, triggers gated, inputs not interpolated into run steps
```

Report: Status + files created.
