---
title: Azure Services - Deployment Template
type: technique
tags: [azure, cloud, credentials, reference-import]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Deployment Template

## What it is

Technical reference for **Azure Services - Deployment Template** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure Resource Manager deployment templates record all parameters used during resource deployments, including connection strings, storage account keys, and other secrets passed as template parameters. An attacker with `Reader` access to a resource group can export deployment templates using `Save-AzResourceGroupDeploymentTemplate`, then search the JSON for hardcoded passwords or sensitive configuration values. Deployment history is retained in the resource group and is accessible to any principal with read access, making it a persistent source of leaked credentials.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

* List the deployments

```powershell
PS Az> Get-AzResourceGroup
PS Az> Get-AzResourceGroupDeployment -ResourceGroupName SAP
```

* Export the deployment template

```ps1
PS Az> Save-AzResourceGroupDeploymentTemplate -ResourceGroupName <RESOURCE GROUP> -DeploymentName <DEPLOYMENT NAME>

# search for hardcoded password
cat <DEPLOYMENT NAME>.json 
cat <PATH TO .json FILE> | Select-String password
```

## References

* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
