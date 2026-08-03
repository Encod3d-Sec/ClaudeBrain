---
title: AWS - Training
type: technique
tags: [aws, cloud, reference-import]
phase: recon
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - Training

## What it is

Technical reference for **AWS - Training** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

AWS training environments such as CloudGoat, AWSGoat, Flaws.cloud, and CloudFoxable deploy intentionally vulnerable AWS infrastructure for practicing enumeration, privilege escalation, and service abuse techniques. Each lab provides a realistic IAM misconfiguration or service vulnerability scenario, ranging from public S3 bucket exposure and metadata SSRF to IAM privilege escalation and Lambda code injection. These environments are used to build fluency with the AWS CLI and offensive tooling before engaging real targets.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

* [bishopfox/CloudFoxable](https://cloudfoxable.bishopfox.com/): A Gamified Cloud Hacking Sandbox
* [ine-labs/AWSGoat](https://github.com/ine-labs/AWSGoat) : A Damn Vulnerable AWS Infrastructure
* [m6a-UdS/dvca](https://github.com/m6a-UdS/dvca) - A demonstration project to show how to do privilege escalation on AWS
* [nccgroup/sadcloud](https://github.com/nccgroup/sadcloud) -  A tool for standing up (and tearing down!) purposefully insecure cloud infrastructure
* [0xdabbad00/Flaws](http://flaws.cloud) - Several level of challenges around AWS
* [RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) - "Vulnerable by Design" AWS deployment tool

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
