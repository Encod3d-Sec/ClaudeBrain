---
title: "AWS Shadow Resources & whoAMI Name Confusion"
type: technique
tags: [aws, cloud, s3, name-confusion, account-takeover, rce, ec2, cloudformation, supply-chain]
phase: exploitation
date_created: 2026-07-02
date_updated: 2026-07-02
sources: [aquasec-bucket-monopoly, datadog-whoami]
---

# AWS Shadow Resources & whoAMI Name Confusion

## What it is

Two AWS name-confusion attack classes that share one root cause: a service resolves a resource by a **predictable or attacker-influenceable name** without verifying the owner.

- **Shadow Resources / Bucket Monopoly** (Aqua): AWS services auto-create S3 buckets with predictable, account-and-region-derived names. An attacker who pre-creates the bucket in a region the victim has not used yet owns the bucket the service later writes to, leading to RCE, data exfiltration, DoS, and account takeover.
- **whoAMI** (Datadog): code that calls `ec2:DescribeImages` with a name filter but no owner filter, plus `most_recent = true`, will select an attacker's public AMI, launching victim compute from an attacker-controlled image (RCE).

Both are name-squatting against automation, close cousins of [[subdomain-takeover]] applied to cloud resource resolution.

## How it works

**Shadow Resources**: several AWS services transparently create an S3 bucket the first time you use a feature in a region. The bucket name is deterministic from your account ID or a per-account hash plus the region. S3 bucket names are global, so an attacker who creates that exact name first, in a region you have not touched, owns it. When you later use the feature there, the service writes your data (CloudFormation templates, Glue ETL scripts, SageMaker datasets) into the attacker's bucket. With a `PutBucketNotification` Lambda, the attacker mutates the data in the read-then-write window (a TOCTOU) before the service consumes it. "Bucket Monopoly" is pre-claiming these names across all AWS regions and waiting.

Attacker-controlled bucket policies restrict the `Principal` to the victim's `arn:aws:iam::{Victim-Account-ID}:root` so the bucket looks legitimate to the service and to a casual audit.

**whoAMI**: `ec2:DescribeImages` returns all public and private images if no owner is specified. A name filter with a wildcard (for example `ubuntu-focal-20.04-amd64-server-*`) matches any AMI whose name starts with that prefix, including one the attacker published publicly. With `most_recent = true`, the newest matching AMI wins, so the attacker just publishes a public AMI with a matching name and a fresh timestamp. The victim's IaC then launches instances from the attacker's image (`aws ec2 run-instances --image-id <attacker-ami>`), giving code execution inside the victim account.

Both feed cloud privilege-escalation chains: see [[cloud-iam-attacks]], [[aws-attacks]], [[aws-service-ec2]], [[aws-service-s3-buckets]].

## Attack phases

- **Recon**: harvest victim account IDs and CloudFormation hashes; enumerate which regions/services the victim has not yet used.
- **Exploitation**: pre-create buckets or publish AMIs; wait for the victim's automation to resolve the name to the attacker's resource.
- **Post-exploitation**: inject an admin IAM role via CloudFormation, run code on the launched EC2 host, or exfiltrate training data; pivot with harvested credentials.

## Prerequisites

Shadow Resources:
- The victim's 12-digit account ID (not secret per AWS: found in ARNs, access-key-derived, GitHub, GrayhatWarfare). For CloudFormation, the 12-char per-account hash (leaked in repos/docs).
- The victim uses an affected service in a region where the predictable bucket does not yet exist.

whoAMI:
- IaC or scripts that call `ec2:DescribeImages` with a name filter, no `owners`/`owner-alias`/`owner-id`, and `most_recent = true`.
- Ability to publish a public AMI (any AWS account).

## Methodology

Shadow Resources / Bucket Monopoly:
1. Collect the target account ID and, for CloudFormation, the account hash.
2. For each affected service, compute the predictable bucket name for every region the victim has not claimed.
3. Create those buckets with a policy scoped to the victim's account root (looks legitimate) and, optionally, a `PutBucketNotification` Lambda to mutate uploaded objects.
4. Wait for the victim to use the service in an unclaimed region; the service writes to your bucket.
5. Escalate per service (CloudFormation template injection for an admin role; Glue/SageMaker code and data injection; DoS by blocking all access).

whoAMI:
1. Find the vulnerable resolution pattern (below).
2. Publish a public AMI whose name matches the victim's name filter with a newer creation date.
3. Wait for the victim's `run-instances`; you now have code execution on their EC2 host, often with an instance-profile role (chain into [[aws-metadata-ssrf]] to read those credentials).

## Key payloads and examples

Predictable shadow-bucket name patterns (create these first to hijack):

```text
CloudFormation   cf-templates-{Hash}-{Region}          # 12-char per-account hash, RCE via template injection
AWS Glue         aws-glue-assets-{Account-ID}-{Region}  # RCE via ETL script injection
Amazon EMR       aws-emr-studio-{Account-ID}-{Region}   # XSS/RCE via notebook injection
SageMaker Canvas sagemaker-{Region}-{Account-ID}        # training-data exfil/manipulation
CodeStar         aws-codestar-{Region}-{Account-ID}     # DoS (service deprecated Jul 2024)
Service Catalog  cf-templates-{Hash}-{Account-ID}       # template injection on product deploy
Athena (legacy)  aws-athena-query-results-{Account-ID}-{Region}  # now requires explicit bucket
AWS CDK bootstrap cdk-hnb659fds-assets-{Account-ID}-{Region}     # static default qualifier hnb659fds
```

Note: `hnb659fds` is CDK's default bootstrap qualifier (a fixed string), so CDK asset-bucket names are predictable from account ID and region alone unless a custom qualifier was set.

Attacker bucket policy that looks legitimate (scopes to the victim account root):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::{Victim-Account-ID}:root"},
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::cf-templates-{Hash}-eu-west-2/*"
  }]
}
```

whoAMI: the vulnerable Terraform pattern (missing `owners`, `most_recent = true`):

```hcl
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  # BUG: no owners = [...]  -> matches attacker's public AMI
}
```

Equivalent vulnerable CLI signature:

```bash
# vulnerable: no --owners, wildcard name, picks most-recent
aws ec2 describe-images --filters "Name=name,Values=ubuntu-focal-20.04-amd64-server-*"
# attacker publishes a public AMI named to match with a newer CreationDate, then victim:
aws ec2 run-instances --image-id <attacker-ami-id> ...
```

## Bypasses and variants

- **Open-source deploy scripts**: SAM/IaC templates that embed `PREFIX-$AWS_ACCOUNT_ID-$AWS_REGION` bucket names are pre-claimable before a developer first runs the deploy, poisoning CI/CD artifacts.
- **DoS variant**: claim the predictable bucket with default block-all-public-access and no policy; the victim's service gets `AccessDenied` and operations fail with cryptic errors. AWS mitigated some services by appending a sequence number on conflict.
- **Cross-account service access**: `aws:ResourceAccount` guards can break legitimate cross-account service flows, so defenders sometimes omit them, reopening the hole.
- **whoAMI beyond Terraform**: any SDK/CLI path (Python `boto3 describe_images`, Go, etc.) with the same missing-owner + most-recent logic is vulnerable; AWS's own internal systems were found pulling matching test AMIs.

## Detection and defence

Shadow Resources:
- Add `aws:ResourceAccount` (or `aws:SourceAccount`) condition keys to identity/resource policies so services only touch buckets your account owns:
```json
{"Condition": {"StringEquals": {"aws:ResourceAccount": "123456789012"}}}
```
- Use `--expected-bucket-owner` on S3 calls; a mismatch returns AccessDenied:
```bash
aws s3 ls s3://aws-glue-assets-123456789012-eu-west-2 --expected-bucket-owner 123456789012
```
- Pre-create the predictable buckets yourself in every region (defensive squatting), or configure services with explicit, unpredictable bucket names using a random per-account/region suffix.
- Treat account IDs and CloudFormation hashes as sensitive; do not leak them in public repos.

whoAMI:
- Enable the account-wide **Allowed AMIs** setting (GA Dec 2024) to allowlist trusted image-provider account IDs; AMIs from other accounts are not discoverable regardless of name.
- Always pin `owners` / `owner-alias` / `owner-id` in `DescribeImages` and `aws_ami` data sources; do not rely on `most_recent = true` for identity.
- Static analysis: a Semgrep rule flagging `aws_ami` blocks with `most_recent = true` that lack an `owners` (or `owner-alias`/`owner-id`/`image-id`) filter; grep CI for `describe-images --filters` without `--owners`.

## Tools

- `aws-cli`: `describe-images`, `s3api`, `--expected-bucket-owner` (see [[aws-cli]]).
- GrayhatWarfare / TrailShark: account-ID and bucket-behaviour reconnaissance.
- Semgrep: the whoAMI Terraform detection rule.
- Prowler / cloud posture scanners: flag missing `aws:ResourceAccount` conditions and Allowed AMIs not enabled.

## Sources

- Aqua Security, "Bucket Monopoly: Breaching AWS Accounts Through Shadow Resources": predictable bucket patterns for CloudFormation, Glue, EMR, SageMaker, CodeStar, Service Catalog; TOCTOU Lambda mutation; `aws:ResourceAccount` and `--expected-bucket-owner` defences (Black Hat USA / DEF CON 32, 2024).
- Datadog Security Labs, "whoAMI: A Cloud Image Name Confusion Attack": missing-owner `DescribeImages` + `most_recent = true`, Terraform `aws_ami` pitfall, Allowed AMIs mitigation, Semgrep detection.
- Related: [[aws-attacks]], [[cloud-iam-attacks]], [[aws-service-s3-buckets]], [[aws-service-ec2]], [[aws-metadata-ssrf]], [[cicd-attacks]], [[subdomain-takeover]].
