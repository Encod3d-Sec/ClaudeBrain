---
title: "Cloud OIDC Trust Abuse and Confused-Deputy Role Assumption"
type: technique
tags: [cloud, oidc, aws, iam, cicd, confused-deputy]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [github-oidc-aws-docs, csp-oidc-github-actions]
---

# Cloud OIDC Trust Abuse and Confused-Deputy Role Assumption

## What it is
Workloads (CI pipelines, especially GitHub Actions) authenticate to a cloud account by presenting a short-lived OIDC token to assume an IAM role, instead of long-lived keys. OIDC trust abuse exploits an over-broad role trust policy: if the condition on the OIDC subject (`sub`) claim is missing or wildcarded, an attacker-controlled workflow, repo, or branch can mint a valid token and assume the role. This is a confused-deputy.

## How it works
The cloud role trusts an OIDC provider (for example token.actions.githubusercontent.com) and is supposed to additionally constrain WHICH identities may assume it via a condition on the `sub` claim (which encodes repo, branch, environment). When the trust policy only checks the provider and audience and omits or wildcards the `sub` condition, any workflow that can obtain a token from that provider can assume the role. For GitHub that means any repo or branch in the org, or any repo at all if org scoping is absent, including an attacker's fork or a pwn-request-controlled workflow.

## Attack phases
Exploitation, lateral movement, and cloud privilege escalation.

## Prerequisites
- A cloud IAM role trusting an OIDC IdP with a missing or wildcarded `sub` condition (or audience-only).
- Ability to run a workflow that requests a token from that IdP (your repo in the org, a fork via pwn request, or any repo when org scoping is absent).

## Methodology
1. Enumerate role trust policies that federate to an OIDC IdP (CI/CD provider, Kubernetes, etc.).
2. Inspect the `Condition` block: is `:sub` constrained to a specific repo:ref/environment, or wildcarded/absent? Is only `:aud` checked?
3. If under-constrained, run a workflow under an identity the policy accepts (your org repo/branch, or a fork via pwn request) with `permissions: id-token: write`.
4. Request the OIDC token and assume the role; you now hold the role's cloud permissions off the intended pipeline.
5. Chain with [[cicd-github-actions]] pwn requests to obtain a token from an untrusted fork.

## Key payloads / examples
Dangerous trust policy (no `sub` condition - any GitHub repo can assume):
```json
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::ACCT:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}
}
```
Wildcarded `sub` (any branch / any repo in pattern) is equally abusable:
```json
"Condition": {"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*"}}
```
Assume from a workflow:
```yaml
permissions:
  id-token: write
steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::ACCT:role/ci-deploy
      aws-region: us-east-1
  - run: aws sts get-caller-identity   # now acting as the role
```

## Bypasses and variants
- Same flaw class across providers: GCP Workload Identity Federation, Azure federated credentials, Kubernetes/EKS IRSA, Terraform Cloud.
- `StringLike` with broad wildcards is as dangerous as no condition at all.
- Reusable across the [[cloud-iam-attacks]] surface; chain with [[cicd-github-actions]] for the initial token.

## Detection and defence
- Constrain `sub` to an exact `repo:ORG/REPO:ref:refs/heads/BRANCH` or `:environment:NAME`; never wildcard `sub`.
- Always check `aud` AND a specific `sub`.
- Scope role permissions to least privilege; alert on AssumeRoleWithWebIdentity from unexpected `sub` values.
- Use environment protection rules so only approved deployments mint privileged tokens.

## Tools
AWS CLI and configure-aws-credentials; cloud IAM policy auditors. See [[cloud-iam-attacks]], [[aws-identity-access-management]], [[cicd-github-actions]].

## Sources
- GitHub Docs, "Configuring OpenID Connect in Amazon Web Services" (slug: github-oidc-aws-docs).
- Cloud Security Partners, "OIDC for GitHub Actions" (slug: csp-oidc-github-actions).
