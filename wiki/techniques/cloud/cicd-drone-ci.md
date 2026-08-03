---
title: CI/CD - Drone CI
type: technique
tags: [cicd, cloud, exploitation, linux, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# CI/CD - Drone CI

## What it is

The configuration files for Drone builds are located in `.drone.yml`\ Drone build are often self-hosted, this means that you may gain excessive privileges to the kubernetes cluster that runs the runners, or to the hosting cloud environment.

## How it works

Drone CI pipelines execute in Docker containers or on self-hosted runners, with secrets injected as environment variables; the pipeline definition lives in `.drone.yml` at the repository root. An attacker with commit access or the ability to trigger a Drone build can modify the pipeline file to add steps that exfiltrate secrets, or exploit the runner's access to the host Kubernetes cluster or cloud environment if the runner is not properly isolated. Self-hosted Drone runners commonly run with elevated cloud permissions that exceed what the pipeline code itself requires.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

The configuration files for Drone builds are located in `.drone.yml`\
Drone build are often self-hosted, this means that you may gain excessive privileges to the kubernetes cluster that runs the runners, or to the hosting cloud environment.

In order to run an OS command in a workflow that builds pull requests - simply add a `commands` instruction to the step.

```yaml
steps:
  - name: do-something
    image: some-image:3.9
    commands:
      - {Payload}
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
