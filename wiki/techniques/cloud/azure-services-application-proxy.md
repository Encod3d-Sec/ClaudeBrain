---
title: Azure Services - Application Proxy
type: technique
tags: [azure, cloud, lateral-movement, reference-import]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Application Proxy

## What it is

Technical reference for **Azure Services - Application Proxy** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure AD Application Proxy publishes on-premises web applications to the internet by routing requests through a connector agent running in the corporate network, authenticating users via Azure AD. Attackers enumerate all Application Proxy-enabled applications to identify internal services exposed externally; any misconfiguration in the backend application itself (SSRF, injection, authentication bypass) is now reachable from the internet. The connector agent running on-premises operates with a managed identity or service account that may have elevated on-premises permissions.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Enumerate

* Enumerate applications that have Proxy

```powershell
PS C:\Tools> Get-AzureADApplication -All $true | %{try{GetAzureADApplicationProxyApplication -ObjectId $_.ObjectID;$_.DisplayName;$_.ObjectID}catch{}}
PS C:\Tools> Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -eq "Finance Management System"}

PS C:\Tools> . C:\Tools\GetApplicationProxyAssignedUsersAndGroups.ps1
PS C:\Tools> Get-ApplicationProxyAssignedUsersAndGroups -ObjectId <OBJECT-ID>
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
