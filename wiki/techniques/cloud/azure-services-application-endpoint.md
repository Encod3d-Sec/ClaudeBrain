---
title: Azure Services - Application Endpoint
type: technique
tags: [azure, cloud, enumeration, reference-import, web]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Application Endpoint

## What it is

Technical reference for **Azure Services - Application Endpoint** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure AD application registrations expose OAuth reply URLs (`ReplyUrls`) and homepage URLs that are used as redirect targets during authentication flows. Attackers enumerate all registered applications to identify ones with misconfigured reply URLs that point to attacker-controllable domains, enabling authorization code interception or open redirect abuse. Applications accessible via the MyApps portal (`myapps.microsoft.com`) can be directly accessed by any tenant user, making overly permissive app assignments a lateral movement vector.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Enumerate

* Enumerate possible endpoints for applications starting/ending with PREFIX

```powershell
PS C:\Tools> Get-AzureADServicePrincipal -All $true -Filter "startswith(displayName,'PREFIX')" | % {$_.ReplyUrls}
PS C:\Tools> Get-AzureADApplication -All $true -Filter "endswith(displayName,'PREFIX')" | Select-Object ReplyUrls,WwwHomePage,HomePage
```

## Access

```ps1
https://myapps.microsoft.com/signin/<App ID>?tenantId=<TenantID>
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
