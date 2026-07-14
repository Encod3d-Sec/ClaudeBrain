---
title: AWS - Service - Lambda & API Gateway
type: technique
tags: [api, aws, cloud, exploitation, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - Service - Lambda & API Gateway

## What it is

Technical reference for **AWS - Service - Lambda & API Gateway** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

Lambda functions execute code with an attached IAM execution role, and any code execution vulnerability (SSRF, injection, dependency confusion) allows retrieval of the role's temporary credentials from the runtime environment variables. Attackers list all Lambda functions, extract their code via `aws lambda get-function`, and analyze it for hardcoded secrets, overly permissive execution roles, or vulnerable dependencies. API Gateway routes that invoke Lambda without authentication or authorization checks are often the initial entry point for triggering serverless code execution.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## List Lambda Functions

```ps1
aws lambda list-functions
```

### Invoke a Lambda Function

```ps1
aws lambda invoke --function-name name response.json --region region 
```

## Extract Function's Code

```powershell
aws lambda list-functions --profile uploadcreds
aws lambda get-function --function-name "LAMBDA-NAME-HERE-FROM-PREVIOUS-QUERY" --query 'Code.Location' --profile uploadcreds
wget -O lambda-function.zip url-from-previous-query --profile uploadcreds
```

## List API Gateway

```ps1
aws apigateway get-rest-apis
aws apigateway get-rest-api --rest-api-id ID
```

## Listing Information About Endpoints

```ps1
aws apigateway get-resources --rest-api-id ID
aws apigateway get-resource --rest-api-id ID --resource-id ID
aws apigateway get-method --rest-api-id ApiID --resource-id ID --http-method method
```

## Listing API Keys

```ps1
aws apigateway get-api-keys --include-values
```

## Getting Information About A Specific Api Key

```ps1
aws apigateway get-api-key --api-key KEY
```

## References

* [Getting shell and data access in AWS by chaining vulnerabilities - Appsecco - Riyaz Walikar - Aug 29, 2019](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
