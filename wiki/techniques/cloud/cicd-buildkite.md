---
title: CI/CD - BuildKite
type: technique
tags: [cicd, cloud, exploitation, linux, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# CI/CD - BuildKite

## What it is

The configuration files for BuildKite builds are located in `.buildkite/*.yml`\ BuildKite build are often self-hosted, this means that you may gain excessive privileges to the kubernetes cluster that runs the runners, or to the hosting cloud environment.

## How it works

BuildKite runners are typically self-hosted on infrastructure controlled by the organization, meaning that code execution in a BuildKite pipeline job runs with whatever privileges the runner host has in the environment, often on Kubernetes clusters or cloud VMs with instance metadata service access. Attackers submit malicious pipeline configurations via a `.buildkite/*.yml` file or inject steps through a poisoned build trigger to execute arbitrary commands on the runner. The runner's Kubernetes service account or cloud instance role then provides lateral movement into the broader infrastructure.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

The configuration files for BuildKite builds are located in `.buildkite/*.yml`\
BuildKite build are often self-hosted, this means that you may gain excessive privileges to the kubernetes cluster that runs the runners, or to the hosting cloud environment.

In order to run an OS command in a workflow that builds pull requests - simply add a `command` instruction to the step.

```yaml
steps:
  - label: "Example Test"
    command: echo "Hello!"
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
