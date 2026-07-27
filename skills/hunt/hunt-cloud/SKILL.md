---
name: hunt-cloud
description: Cloud attack hunting for AWS / Azure / GCP - credential discovery, metadata SSRF, IAM privesc, service enumeration, persistence. Scope + billing aware. Wiki-first, FIND schema output.
---

# Hunt: Cloud (AWS / Azure / GCP)

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "cloud AWS Azure GCP metadata SSRF IAM privilege escalation credential discovery persistence" via wiki-search MCP
```

Hub: [[cloud-moc]] (live index). Primary page: [[cloud-iam-attacks]]. Payload arsenal: `wiki/payloads/imds-cloud-metadata.md`.
Anchors: [[aws-metadata-ssrf]] (SSRF -> IMDS creds), [[azure-ad-iam]].

## Billing and safety (cloud-specific)

`hunt-core` owns the scope gate. Cloud stacks three specifics on top of it:

- **Scope is account / subscription / project IDs**, not just hostnames. Confirm the ID is in scope before the first authenticated call.
- **Every call is billed and logged** (CloudTrail / Azure Activity / GCP Audit Logs). Enumeration is loud, costs the client, and mass API calls trip provider abuse detection (GuardDuty / Defender). Prefer read-only enumeration, keep call volume low, and create or delete NOTHING without RoE sign-off.
- **Never spray IAM users** (lockout + GuardDuty). Reuse keys from `loot.md` first.

## Attack surface (ranked)

1. **Metadata SSRF** - an app-side SSRF reaching `169.254.169.254` / `metadata.google.internal` hands you instance/managed-identity creds. Highest-value chain.
2. **Exposed keys** - `.env`, `~/.aws/credentials`, CI/CD vars, JS bundles, git history: `AKIA*`/`ASIA*` (AWS), `AccountKey=` (Azure), `"type":"service_account"` JSON (GCP).
3. **Over-privileged roles** - creds in hand whose IAM grants a privesc primitive (step 4).
4. **Public storage** - S3 `*.s3.amazonaws.com`, Azure `*.blob.core.windows.net`, GCS `storage.googleapis.com/<bucket>`. Ranked last: frequently non-sensitive, easy to over-claim.

**Chaining:** SSRF that reaches the metadata endpoint -> pull IMDS creds; this is a hand-off from / to `hunt-ssrf` (that skill owns reaching the endpoint, this one owns what the creds unlock). A leaked key -> IAM enumeration -> privesc chain (step 4).

**Evasion:** AWS IMDSv2 needs a session token first (`PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`, then `X-aws-ec2-metadata-token` on the GET) - an SSRF that cannot set headers only reaches IMDSv1. Enumeration is logged: prefer a compromised in-account principal over external calls, and read-only actions over anything that writes an audit event you cannot explain.

## Tooling-first: install the CLI, do NOT hand-roll REST (Azure especially)
The provider CLIs and `roadrecon` do enumeration + attack in one authenticated call - **install them
FIRST**; hand-rolled `curl`/`urllib` against Graph/ARM is the drift to avoid (weaker, no paging, easy
to misquote). Reach for a script only for the rare thing the CLI can't express.
- **Azure creds in hand?** `az login -u <upn> -p <pass>` (ROPC; works on Managed tenants when the CLI
  client isn't MFA-gated). Then `az account show`, `az account list`, `az resource list -o table`,
  `az vm list -d -o table`, `az role assignment list --all`. Entra dump = **roadrecon** (`roadrecon auth
  -r <refresh-token>` reuses a token cross-client via FOCI, no password quoting; then `roadrecon dump`).
  AzureHound for attack paths; MicroBurst `Get-AzPasswords` (pwsh) to sweep KV/automation/storage secrets.
- **az cli on Kali gotcha:** the deb repo rejects Kali's dist codename ("Unable to find a package for
  your system"). Install with `curl -sL https://aka.ms/InstallAzureCLIDeb | DIST_CODE=bookworm bash`,
  or just run az on the target Ubuntu VM where it installs cleanly.
- **Compromised an Azure compute resource (VM/App Service/Container)?** Don't parse IMDS JSON by hand -
  `az login --identity` authenticates AS that resource's managed identity straight from IMDS; then use
  az normally. `az account show` confirms `user.type=servicePrincipal` / `systemAssignedIdentity`.

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
3. **Enumerate permissions** (read-only IAM discovery of the account you already hold - legitimate per `hunt-core`, but each of these fans out into many billed, logged API calls, so scope tightly and do not loop them):
```bash
aws iam get-account-authorization-details;  enumerate-iam --access-key ... --secret-key ...   # or pacu
az role assignment list --assignee <id>;  ScoutSuite azure
gcloud projects get-iam-policy <proj>;  curl https://... (roadtools / ROADrecon for Entra)
```
4. **IAM privesc:** AWS (`iam:PassRole`+lambda/ec2, `sts:AssumeRole`, policy version, `iam:CreateAccessKey`); Azure (Owner/Contributor on subscription, `Microsoft.Authorization/*`, managed identity abuse, Automation runbooks); GCP (`iam.serviceAccounts.actAs`, `setIamPolicy`, deployment manager, `actAs` chains).
5. **Service loot:** S3/blob/GCS objects, Secrets Manager / Key Vault / Secret Manager, SSM parameters, Lambda/Function env, snapshots, EBS, Storage Account keys.
6. **Lateral / persistence (RoE-gated):** assume cross-account role, new access key, SSH key to instance metadata, service-account key creation, Automation account runbook.
7. **Distill (when confirmed):** stage a GENERIC technique (no client host) to the most relevant cloud page: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/cloud-iam-attacks.md`. Full protocol in `hunt-core`.

## Confirmation gate

**NOT confirmation:** an enumerated bucket / blob / GCS name; a role ARN or service-account email you listed but never assumed; a metadata endpoint that merely responds; `AKIA*` / `AccountKey=` / service-account JSON found but never exercised; a `200` from a permissions enumerator that only reads policy, not access.

**IS confirmation:** credentials actually retrieved AND validated with a SINGLE benign read-only call that names the principal (`aws sts get-caller-identity`, `az account show`, `gcloud auth list`), or a resource actually read cross-account / cross-tenant - reproduced in a clean session. One benign call proves control: stop there. Do NOT spin up resources or mass-enumerate to "prove more" - that only adds billing, audit noise, and abuse-detection risk without changing the finding.

## Severity

CRITICAL = creds to admin/owner, cross-account/tenant takeover, metadata role creds. HIGH = sensitive data read (secrets/buckets), IAM privesc path. MEDIUM = enumeration / public bucket with non-sensitive data.

## Context tools

<!-- auto-wired: documented tools to reach for; do not hand-roll -->
- [[aws]]
