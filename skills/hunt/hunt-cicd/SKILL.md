---
name: hunt-cicd
description: CI/CD pipeline attack hunting (GitHub Actions focus) - pwn requests (pull_request_target), script injection, self-hosted runner takeover, cache poisoning, OIDC-to-cloud token theft, poisoned pipeline execution. Wiki-first, FIND schema output.
---

# Hunt: CI/CD Pipeline Attacks

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "CI/CD GitHub Actions pull_request_target pwn request script injection self-hosted runner OIDC cache poisoning" via wiki-search MCP
```

Hub: [[cloud-moc]] (live index). Primary page: [[cicd-github-actions]]. Payload arsenal: `wiki/payloads/cicd.md`.
Anchors: [[supply-chain-attacks]], [[cloud-oidc-trust-abuse]] (OIDC role assumption off-box), [[cicd-attacks]] (cross-platform CI/CD).

## Attack surface (ranked)

1. **Pwn requests (`pull_request_target` / `workflow_run`)** - the highest-value bug. A workflow that runs on `pull_request_target`, checks out the fork HEAD, and holds secrets executes attacker code in the trusted (secret-bearing) context. Fork, inject a build step, open a PR, exfil `env` / secrets / `GITHUB_TOKEN`.
2. **Script injection via untrusted `${{ }}`** - `github.event.*` values (PR title, branch name, issue body, review comment) interpolated directly into a `run:` step. Attacker controls the string, so the string becomes shell.
3. **Self-hosted runner takeover** - non-ephemeral runners persist state between jobs and are shared across a repo/org pool. A pwn request or script injection landing on one is persistence and cross-repo reach, not a one-shot.
4. **OIDC-to-cloud token theft** - `permissions: id-token: write` mints a cloud-assumable JWT. Weak trust-policy `sub` scoping (wildcard repo/ref) lets a fork job assume the role off-box. Chains to `hunt-cloud`.

Signals to grep the repo for: `.github/workflows` with `pull_request_target`/`workflow_run`; untrusted `${{ github.event.* }}` inside `run:`; self-hosted runner labels; `id-token: write`; `actions/cache` restored across trust boundaries.

## Methodology

1. **Enumerate workflows + triggers** - gato / Gato-X, octoscan, poutine. Read every workflow end-to-end (each `run:`, each referenced action, each reusable-workflow `uses:`), not a keyword grep - the injectable sink hides in a called composite action.
2. **Pwn request** - a `pull_request_target` (or `workflow_run`) workflow that checks out the fork HEAD and holds secrets: fork, inject a build step, open a PR, exfil `env` / secrets / `GITHUB_TOKEN` to your sink.
3. **Script injection** - inject `a"; <cmd>; #` (or `$(<cmd>)` / backticks per shell) into a `github.event.*` value that lands in a `run:` step. Use a unique canary in the command output, per hunt-core marker discipline, so you can prove YOUR injection ran.
4. **Self-hosted runner** - non-ephemeral = persistence between jobs + cross-repo on a shared pool. Once you have execution, confirm the runner type (ephemeral vs long-lived) before claiming persistence.
5. **Cache poisoning** - a fork job writes an `actions/cache` entry that a trusted base job later restores, moving attacker-controlled content across the trust boundary.
6. **OIDC theft** - pull `ACTIONS_ID_TOKEN_REQUEST_TOKEN` / `ACTIONS_ID_TOKEN_REQUEST_URL`, request the JWT, assume the cloud role off-box; inspect trust-policy `sub` scoping for over-broad repo/ref wildcards. Hand off to `hunt-cloud`.
7. **PPE (poisoned pipeline execution)** - modify a `Makefile` / `package.json` / build script the pipeline runs, bypassing CODEOWNERS that only guards the workflow files themselves.
8. **Confirm** - see the confirmation gate below.
9. **Distill (when confirmed)** - reusable pwn-request / OIDC-theft / PPE technique, GENERIC, no client repo: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/cicd-github-actions.md`.

## Confirmation gate

**NOT confirmation:** a workflow that merely *looks* injectable; a `pull_request_target` trigger present in isolation; untrusted `${{ }}` sitting in a `run:` step you have not shown executing; `id-token: write` declared without an assumed role; "the PR ran" with no output proving your code ran; a secret name visible in the workflow YAML.

**IS confirmation:** your injected code/command actually executed in the pipeline's trusted context (canary command output in the job log), OR a secret / `GITHUB_TOKEN` / OIDC token actually exfiltrated to your sink, OR a cloud role actually assumed off-box (STS identity returned) - reproduced from your written steps.

## Stop condition

A pipeline compromise is high-impact and persistent (secret-bearing context, shared runners, cloud roles). Per hunt-core stop conditions, once the primitive is proven, stop. Prove execution with a **benign** canary echo or an OOB callback; prove exfil against **your own** sink. Do NOT tamper with production artifacts, publish a release, push to a protected branch, or leave content that outlives the run. The demonstrated primitive is the finding; escalation past it adds risk, not payout.

## Chaining

OIDC token theft or secret exfil hands off to `hunt-cloud` (assume the role, enumerate the account) - the CI/CD bug is the delivery, the cloud access is the impact. A leaked `GITHUB_TOKEN` with `contents:write`/`packages:write` chains to supply-chain reach ([[supply-chain-attacks]]).

## Evasion

CODEOWNERS and required reviews typically guard `.github/workflows/**` only; PPE (step 7) reaches execution through a build script they do not cover. Branch-name and PR-title injection sidesteps content review entirely (the trigger fires before merge). Prefer `workflow_run` and cache paths when `pull_request_target` is locked down.

## Severity

CRITICAL if OIDC-to-cloud role assumption or `GITHUB_TOKEN`/secret exfil; HIGH if pwn-request / script-injection RCE on a runner; MEDIUM if cache poisoning with limited reach.
