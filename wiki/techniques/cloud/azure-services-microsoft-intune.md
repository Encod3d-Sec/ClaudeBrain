---
title: Azure Services - Microsoft Intune
type: technique
tags: [azure, cloud, intune, lateral-movement, reference-import]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Microsoft Intune

## What it is

Microsoft Intune is a cloud-based service that provides mobile device management (MDM) and mobile application management (MAM). It allows organizations to control and secure access to corporate data on mobile devices, including smartphones, tablets, and PCs. With Intune, businesses can enforce security policies, manage apps, and ensure that devices comply with organizational requirements, whether they are company-owned or personal (BYOD).

## How it works

Intune enforces MDM policies on enrolled devices and is used by Conditional Access Policies to require device compliance before granting resource access. Attackers compromise Intune by escalating to the `Intune Administrator` or `Global Administrator` role, then push malicious device configuration profiles or PowerShell scripts to all managed Windows devices, achieving organization-wide code execution. Alternatively, attackers can fake device compliance by manipulating device enrollment metadata or by enrolling an attacker-controlled VM, bypassing CAP device-compliance requirements.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

Microsoft Intune is a cloud-based service that provides mobile device management (MDM) and mobile application management (MAM). It allows organizations to control and secure access to corporate data on mobile devices, including smartphones, tablets, and PCs. With Intune, businesses can enforce security policies, manage apps, and ensure that devices comply with organizational requirements, whether they are company-owned or personal (BYOD).

## Intunes Administration

**Requirements**:

* **Global Administrator** or **Intune Administrator** Privilege

```powershell
Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"
```

**Walkthrough**

1. Login into <https://endpoint.microsoft.com/#home> or use Pass-The-PRT
2. Go to **Devices** -> **All Devices** to check devices enrolled to Intune
3. Go to **Scripts** and click on **Add** for Windows 10.
4. Add a **Powershell script**
5. Specify **Add all users** and **Add all devices** in the **Assignments** page.

:warning: It will take up to one hour before you script is executed !

## Intune Scripts

**Requirements**:

* App with permission: `DeviceManagementConfiguration.Read.All`
* `Microsoft.Graph.Intune` dependency installed: `Install-Module Microsoft.Graph.Intune`

**Extract Intune scripts**:

The following scripts are deprecated, use `MgGraph` instead of `MsGraph`, and change the appropriate function `InvokeMgGraph` too.

* [okieselbach/Get-DeviceManagementScripts.ps1](https://raw.githubusercontent.com/okieselbach/Intune/master/Get-DeviceManagementScripts.ps1) - Get all or individual Intune PowerShell scripts and save them in specified folder.

```ps1
Get-DeviceManagementScripts -FolderPath C:\temp -FileName myScript.ps1
```

* [okieselbach/Get-DeviceHealthScripts.ps1](https://raw.githubusercontent.com/okieselbach/Intune/master/Get-DeviceHealthScripts.ps1) - Get all or individual Intune PowerShell Health scripts (aka Proactive Remediation scripts) and save them in specified folder.

```ps1
Get-DeviceHealthScripts -FolderPath C:\temp\HealthScripts
```

* [secureworks/pytune](https://github.com/secureworks/pytune) - Pytune is a post-exploitation tool for enrolling a fake device into Intune with mulitple platform support.

```ps1
python3 pytune.py entra_join -o Windows -d Windows_pytune -u testuser@*******.onmicrosoft.com -p ***********  
python3 pytune.py enroll_intune -o Windows -d Windows_pytune -c Windows_pytune.pfx -u testuser@*******.onmicrosoft.com -p *********** 
python3 pytune.py download_apps -d Windows_pytune -m Windows_pytune_mdm.pfx
```

## LAPS

Some organization have recreated LAPS for Azure devices using Intune scripts.

```ps1
#requires -modules Microsoft.Graph.Authentication
#requires -modules Microsoft.Graph.Intune
#requires -modules LAPS
#requires -modules ImportExcel

$DaysBack = 30
Connect-MgGraph
Get-IntuneManagedDevice -Filter "Platform eq 'Windows'" |
    Foreach-Object {Get-LapsAADPassword -DevicesIds $_.DisplayName} |
        Where-Object {$_.PasswordExpirationTime -lt (Get-Date).AddDays(-$DaysBack)} |
            Export-Excel -Path "c:\temp\lapsdata.xlsx" - ClearSheet -AutoSize -Show
```

## References

* [Microsoft Intune - Microsoft Intune support for Windows LAPS](https://learn.microsoft.com/en-us/mem/intune/protect/windows-laps-overview)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)
* [Get back your Intune Proactive Remediation Scripts - Oliver Kieselbach - September 7, 2022](https://oliverkieselbach.com/2022/09/07/get-back-your-intune-proactive-remediation-scripts/)
* [Get back your Intune PowerShell Scripts - Oliver Kieselbach - February 6, 2020](https://oliverkieselbach.com/2020/02/06/get-back-your-intune-powershell-scripts/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
