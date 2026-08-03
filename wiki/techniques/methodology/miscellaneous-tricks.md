---
title: Miscellaneous & Tricks
type: technique
tags: [active-directory, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Miscellaneous & Tricks

## What it is

All the tricks that couldn't be classified somewhere else.

## How it works

This page collects miscellaneous Windows, Linux, and AD techniques that do not fit neatly into a single attack category, such as Kerberos clock skew synchronization, file staging methods, and tool-specific quirks. Many of these tricks are prerequisite steps or workarounds that enable primary attacks to function correctly in edge-case environments, such as adjusting system time to satisfy Kerberos ticket validity windows or working around non-standard network configurations. These techniques are referenced by other pages when a specific environmental prerequisite must be met before a main exploit can proceed.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

All the tricks that couldn't be classified somewhere else.

## Send Messages to Other Users

* Windows

```powershell
PS C:\> msg Swissky /SERVER:CRASHLAB "Stop rebooting the XXXX service !"
PS C:\> msg * /V /W /SERVER:CRASHLAB "Hello all !"
```

* Linux

```powershell
wall "Stop messing with the XXX service !"
wall -n "System will go down for 2 hours maintenance at 13:00 PM"  # "-n" only for root
who
write root pts/2 # press Ctrl+D  after typing the message. 
```

## NetExec Credential Database

```ps1
nxcdb (default) > workspace create test
nxcdb (test) > workspace default
nxcdb (test) > proto smb
nxcdb (test)(smb) > creds
nxcdb (test)(smb) > export creds csv /tmp/creds
```

NetExec workspaces

```ps1
# get current workspace
poetry run nxcdb -gw 

# create workspace
poetry run nxcdb -cw testing

# set workspace
poetry run nxcdb -sw testing 
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[netexec]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
