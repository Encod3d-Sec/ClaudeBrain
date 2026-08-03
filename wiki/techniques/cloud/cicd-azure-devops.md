---
title: CI/CD - Azure DevOps
type: technique
tags: [azure, cicd, cloud, exploitation, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# CI/CD - Azure DevOps

## What it is

The configuration files for azure pipelines are normally located in the root directory of the repository and called - `azure-pipelines.yml`\ You can tell if the pipeline builds pull requests based on its trigger instructions. Look for `pr:` instruction:.

## How it works

Azure Pipelines configured with a `pr:` trigger execute pipeline jobs for pull requests from forked repositories, allowing external contributors to inject arbitrary YAML pipeline steps. Malicious pipeline steps execute with the service connection permissions of the pipeline, which frequently include cloud credentials, SSH keys, or API tokens stored as pipeline secrets. An attacker who controls a forked repository or can submit a pull request can exfiltrate all pipeline secrets by echoing them to pipeline output or sending them to an external endpoint.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Azure Pipelines

The configuration files for azure pipelines are normally located in the root directory of the repository and called - `azure-pipelines.yml`\
You can tell if the pipeline builds pull requests based on its trigger instructions. Look for `pr:` instruction:

```yaml
trigger:
  branches:
      include:
      - master
      - refs/tags/*
pr:
- master
```

## Secret Extractions

Extract secrets for these service connection:

* AzureRM
* GitHub
* AWS
* SonarQube
* SSH

```ps1
nord-stream.py devops ... --build-yaml test.yml --build-type ssh  
```

## References

* [Azure DevOps CICD Pipelines - Command Injection with Parameters, Variables and a discussion on Runner hijacking - Sana Oshika - May 1 2023](https://pulsesecurity.co.nz/advisories/Azure-Devops-Command-Injection)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
