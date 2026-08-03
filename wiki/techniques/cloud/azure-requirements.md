---
title: Azure - Requirements
type: technique
tags: [azure, cloud, enumeration, reference-import]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure - Requirements

## What it is

Users and roles:.

## How it works

Azure assessments require at minimum a `Global Reader` and `Security Reader` role in Azure AD plus `Reader` permission on the subscription to perform comprehensive enumeration without modifying resources. A Visual Studio or Dev/Test subscription provides Azure credits needed to spin up lab infrastructure for testing exploitation chains. The key PowerShell modules for assessment are Microsoft.Graph, AzureAD, and the Az module (`Az.Accounts`, `Az.Resources`), which authenticate via interactive login or service principal credentials.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Pentest Requirements

Users and roles:

* **Global Reader** and **Security Reader** roles in Azure AD
* **Reader** permission over the subscription

Subscriptions:

* [Azure Dev/Test](https://azure.microsoft.com/en-us/pricing/offers/dev-test) subscription.
* Visual Studio subscription determines the monthly Azure credits you receive
    * Visual Studio Enterprise: $150/month
    * MSDN Platforms: $100
    * Visual Studio Professional: $50
    * Visual Studio Test Professional: $50

## Powershell and Native Modules

* [Microsoft Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0): `Install-Module Microsoft.Graph -Scope CurrentUser`
* [Azure AD](https://learn.microsoft.com/fr-fr/powershell/azure/active-directory/install-adv2?view=azureadps-2.0): `Install-Module AzureAD`
* [Azure AD Preview](https://learn.microsoft.com/fr-fr/powershell/azure/active-directory/install-adv2?view=azureadps-2.0): `Install-Module AzureADPreview`
* [Azure CLI](https://learn.microsoft.com/fr-fr/cli/azure/install-azure-cli-windows?tabs=winget): `winget install -e --id Microsoft.AzureCLI`

## Terminology

* **Tenant**: An instance of Azure AD and represents a single organization.
* **Azure AD Directory**: Each tenant has a dedicated Directory. This is used to perform identity and access management functions for resources.
* **Subscriptions**: It is used to pay for services. There can be multiple subscriptions in a Directory.
* **Core Domain**: The initial domain name `<tenant>.onmicrosoft.com` is the core domain. It is possible to define custom domain names too.

## References

* [Az - Permissions for a Pentest - HackTricks](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-permissions-for-a-pentest)
* [An introduction to penetration testing Azure - HollyGraceful - 06 August 2021](https://akimbocore.com/article/introduction-to-pentesting-azure/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
