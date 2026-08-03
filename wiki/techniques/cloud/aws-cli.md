---
title: AWS - CLI
type: technique
tags: [aws, cloud, enumeration, reference-import]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - CLI

## What it is

The AWS Command Line Interface (CLI) is a unified tool to manage AWS services from the command line. Using the AWS CLI, you can control multiple AWS services, automate tasks, and manage configurations through profiles.

## How it works

The AWS CLI authenticates using credentials stored in `~/.aws/credentials` or injected via environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), and sends signed API requests to AWS service endpoints. During an assessment, attackers configure the CLI with captured credentials and use it to enumerate IAM permissions, list resources, and pivot between services. Chaining CLI commands across services (EC2 instance profiles, S3, SSM, Lambda) reveals privilege escalation paths that are not obvious from any single service view.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

The AWS Command Line Interface (CLI) is a unified tool to manage AWS services from the command line. Using the AWS CLI, you can control multiple AWS services, automate tasks, and manage configurations through profiles.

## Set up AWS CLI

Install AWS CLI and configure it for the first time:

```ps1
aws configure
```

This will prompt for:

* AWS Access Key ID
* AWS Secret Access Key
* Default region name
* Default output format

## Creating Profiles

You can configure multiple profiles in `~/.aws/credentials` and `~/.aws/config`.

* `~/.aws/credentials` (stores credentials)

```ini
[default]
aws_access_key_id = <default-access-key>
aws_secret_access_key = <default-secret-key>

[dev-profile]
aws_access_key_id = <dev-access-key>
aws_secret_access_key = <dev-secret-key>

[prod-profile]
aws_access_key_id = <prod-access-key>
aws_secret_access_key = <prod-secret-key>
```

* `~/.aws/config` (stores region and output settings)

```ini
[default]
region = us-east-1
output = json

[profile dev-profile]
region = us-west-2
output = yaml

[profile prod-profile]
region = eu-west-1
output = json
```

You can also create profiles via the command line:

```ps1
aws configure --profile dev-profile
```

## Using Profiles

When running AWS CLI commands, you can specify which profile to use by adding the `--profile` flag:

```ps1
aws s3 ls --profile dev-profile
```

If no profile is specified, the **default** profile is used.

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
