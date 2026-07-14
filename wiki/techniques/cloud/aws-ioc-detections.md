---
title: AWS - IOC & Detections
type: technique
tags: [aws, cloud, reference-import]
phase: recon
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - IOC & Detections

## What it is

Technical reference for **AWS - IOC & Detections** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

AWS CloudTrail logs all API calls including the caller identity, source IP, time, and requested action, making it the primary detection source for malicious AWS activity. Attackers who gain initial access often attempt to disable CloudTrail, delete log groups, or create logging exemptions to reduce visibility; these actions are themselves logged until the trail is fully disabled and are detectable by GuardDuty. Defenders correlate CloudTrail events with GuardDuty findings and VPC flow logs to identify credential abuse, lateral movement between services, and data exfiltration patterns.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## CloudTrail

### Disable CloudTrail

```powershell
aws cloudtrail delete-trail --name cloudgoat_trail --profile administrator
```

Disable monitoring of events from global services

```powershell
aws cloudtrail update-trail --name cloudgoat_trail --no-include-global-service-event 
```

Disable Cloud Trail on specific regions

```powershell
aws cloudtrail update-trail --name cloudgoat_trail --no-include-global-service-event --no-is-multi-region --region=eu-west
```

## GuardDuty

### OS User Agent

:warning: When using awscli on Kali Linux, Pentoo and Parrot Linux, a log is generated based on the user-agent.

Pacu bypass this problem by defining a custom User-Agent: [pacu.py#L1473](https://web.archive.org/web/20201111195614/https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu.py#L1303)

```python
boto3_session = boto3.session.Session()
ua = boto3_session._session.user_agent()
if 'kali' in ua.lower() or 'parrot' in ua.lower() or 'pentoo' in ua.lower():  # If the local OS is Kali/Parrot/Pentoo Linux
    # GuardDuty triggers a finding around API calls made from Kali Linux, so let's avoid that...
    self.print('Detected environment as one of Kali/Parrot/Pentoo Linux. Modifying user agent to hide that from GuardDuty...')
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[pacu]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
