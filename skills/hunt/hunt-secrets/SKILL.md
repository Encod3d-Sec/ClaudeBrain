---
name: hunt-secrets
description: Exposed-secrets hunting - .git/ dir + history mining, exposed .env/config files, hardcoded keys in JS bundles + source maps, S3/blob exposure, public-repo secret search, CI/CD leakage. Live-validation mandatory. Wiki-first, FIND schema output.
---

# Hunt: Exposed Secrets / Credential Exposure

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "exposed secrets git exposure hardcoded credentials source maps" via wiki-search MCP -> read matching technique page if found.
```
Apply documented dorks, extraction patterns, and validation steps. Wiki refs: [[git-exposure]], [[secret-hunting]], [[hardcoded-secrets-enumeration]], [[source-code-analysis]], [[javascript-source-map-exploitation]], [[aws-service-s3-buckets]], [[aws-access-token-secrets]], [[supply-chain-attacks]]. Dork lists: [[recon-dorks]].


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target (host, repo, bucket) is in scope
- Read Deadends.md - skip assets already mined dry
- Honor RoE: a secret in a public repo is fair game; do NOT act on creds for out-of-scope third-party systems

## Validation Gate (Read First)
**Do not report a string because it looks like a secret. Confirm it is LIVE and unrotated.**

NOT confirmation: high-entropy string, a var named `API_KEY`, a key in old git history with no validation, an `.env.example` placeholder.
IS confirmation: an authenticated API call that succeeds with the secret, or a service-specific validity check returning 200/valid.

## Attack Surface Signals
Path probes: `/.git/`, `/.env`, `/.env.local`, `/.env.prod`, `/.git-credentials`, `/.aws/credentials`, `/config.json`, `/wp-config.php.bak`, `/.npmrc`, `/.netrc`, `/backup.zip`, `/.DS_Store`
Client-side: inline `<script>`, `main.*.js` bundles, `*.js.map` source maps, webpack chunks, `__NEXT_DATA__`, embedded `firebaseConfig`.
Buckets/blobs: `s3.amazonaws.com/<name>`, `<name>.s3.<region>.amazonaws.com`, `*.blob.core.windows.net`, `storage.googleapis.com/<name>`.
Repos: GitHub/GitLab org + employee personal repos, gists, forks, deleted-but-cached commits.

## Methodology
1. Probe exposed dotfiles/configs with curl:
```bash
for p in .env .env.local .git/HEAD .git-credentials .aws/credentials .npmrc config.json; do
  printf '%s -> ' "$p"; curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/$p"
done
```
2. Exposed `.git/` -> dump full repo, then mine history:
```bash
# /.git/HEAD returning a ref = exposed
curl -s https://target.com/.git/HEAD
git-dumper https://target.com/.git/ ./dump   # or wget -r the .git index
trufflehog filesystem ./dump --only-verified
gitleaks detect --source ./dump --no-banner
```
3. JS bundle + source map extraction:
```bash
# pull bundles, grep for key shapes
curl -s https://target.com/static/js/main.js | grep -Eo \
  '(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{24}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+)'
# rebuild original source from a source map, then trufflehog it
npx source-map-explorer main.js main.js.map 2>/dev/null
trufflehog filesystem ./bundles --only-verified
```
4. S3 / blob enumeration:
```bash
aws s3 ls s3://<name> --no-sign-request          # public list
aws s3 sync s3://<name> ./bucket --no-sign-request
curl -s "https://storage.googleapis.com/<name>/" # GCS listing
curl -s "https://<name>.blob.core.windows.net/?comp=list"  # Azure blob
```
5. Public-repo + org search:
```bash
trufflehog github --org=<org> --only-verified
# manual dorks (see [[recon-dorks]]):
#   "target.com" password   filename:.env   org:<org>
gitleaks detect --source ./cloned-repo --no-banner
```
6. CI/CD leakage: check build logs, GitHub Actions artifacts, `pull_request_target` output, exposed `.gitlab-ci.yml` vars, printed env in public job logs.
7. Collect every candidate secret with its type tag (aws/gcp/slack/stripe/github/db-uri) for the validation step.
8. **Distill to wiki (when confirmed):** if the finding is a reusable exposure vector, extraction trick, or key-validation endpoint, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/osint/secret-hunting.md` (or `git-exposure.md` / `source-code-analysis.md` as fitting). Promote later via `scripts/wiki-promote.py`.

## Verification / Validation
Validate each candidate against its service before reporting. Live + unrotated only.
```bash
# AWS
aws sts get-caller-identity                       # creds in env/profile
# GitHub token
curl -s -H "Authorization: token $GH" https://api.github.com/user
# Slack
curl -s -d "token=$SLACK" https://slack.com/api/auth.test
# Stripe
curl -s https://api.stripe.com/v1/charges -u "$SK:"
# Google API key
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=$KEY"
```
trufflehog `--only-verified` already performs live checks; still re-confirm scope-impacting creds manually. A rotated/invalid key is a Deadend, not a finding (note it as info-disclosure only if the exposure path itself is the issue).

## FIND Output

If finding confirmed (secret validated LIVE):
```
Create Vulns/Research/FIND-XXX-SEVERITY-secret-exposure-<host>-<type>.md
Add row to Vuln-index.md: | FIND-XXX | <type> key exposed via <vector> | <host/repo> | PARTIAL |
Severity: CRITICAL if cloud/admin/prod-DB creds or org-wide token; HIGH if scoped prod API key / service token; MEDIUM if limited-scope key or read-only; LOW if low-value/rotated key with exposure path only
```

If path exhausted (dotfile probes 404, no .git, bundles clean, buckets private, repos dry, candidates all rotated):
```
Append to Deadends.md: - [ ] Secret exposure on <host/repo> -- .git absent, configs 404, bundles + source maps clean, candidates invalid/rotated
```

Report: Status + files created.
