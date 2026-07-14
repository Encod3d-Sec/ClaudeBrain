---
title: CI/CD - CircleCI
type: technique
tags: [cicd, cloud, exploitation, linux, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# CI/CD - CircleCI

## What it is

The configuration files for CircleCI builds are located in `.circleci/config.yml`\ By default - CircleCI pipelines don't build forked pull requests. It's an opt-in feature that should be enabled by the pipeline owners.

## How it works

CircleCI pipelines store organization secrets as context variables and project-level environment variables that are injected into pipeline jobs at execution time. By default CircleCI does not build forked pull requests, but when that option is enabled, an external contributor can trigger a pipeline job that receives these secrets. Attackers who gain write access to a repository or who can trigger builds via API tokens can extract secrets by adding a step that prints environment variables or exfiltrates them to an external server.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

The configuration files for CircleCI builds are located in `.circleci/config.yml`\
By default - CircleCI pipelines don't build forked pull requests. It's an opt-in feature that should be enabled by the pipeline owners.

In order to run an OS command in a workflow that builds pull requests - simply add a `run` instruction to the step.

```yaml
jobs:
  build:
    docker:
     - image: cimg/base:2022.05
    steps:
        - run: echo "Say hello to YAML!"
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
