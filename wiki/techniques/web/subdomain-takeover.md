---
title: "Subdomain Takeover"
type: technique
tags: [cloud, dns, h1, recon, subdomain-takeover, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [h1-scraped-subdomain-takeover]
---

## What it is

A subdomain takeover occurs when a DNS record (typically CNAME) points to an external service or cloud resource that has been deprovisioned or deleted. An attacker who registers that resource can serve content under the victim's subdomain, enabling phishing, cookie theft, CORS bypass, or CSP bypass.

## How it works

1. A company creates `cdn.company.com CNAME assets.provider.com` for a CDN or cloud service
2. The cloud resource is later deleted (S3 bucket removed, Fastly/CloudFront distribution deleted, GitHub Pages repo removed)
3. The CNAME still resolves but the upstream resource returns a "bucket not found" or similar dangling response
4. An attacker registers the same resource name at the provider and now controls content served at `cdn.company.com`

## Common vulnerable services

- AWS S3 (unclaimed bucket name)
- Azure App Service / Blob Storage
- Fastly (unregistered service)
- CloudFront (unregistered distribution)
- GitHub Pages (repo deleted, CNAME still set)
- Heroku (app deleted)
- Shopify / Tumblr / Zendesk (custom domain CNAME to deleted shop/page)

## Methodology

1. Enumerate subdomains: `subfinder`, `amass`, `dnsx`, `chaos`
2. Check CNAMEs: `dig CNAME sub.target.com` — look for dangling pointers
3. Request the subdomain — watch for provider-specific "not found" pages (e.g., "NoSuchBucket", "There isn't a GitHub Pages site here", "Fastly error: unknown domain")
4. Identify the provider from the CNAME target or error page
5. Register/claim the resource at the provider with the exact name
6. Serve a proof-of-concept page from the claimed resource

## Key signals (dangling service fingerprints)

| Provider | Error indicator |
|----------|----------------|
| AWS S3 | `NoSuchBucket` or `The specified bucket does not exist` |
| GitHub Pages | `There isn't a GitHub Pages site here` |
| Fastly | `Fastly error: unknown domain` |
| Heroku | `No such app` |
| CloudFront | `Bad request` on custom domain with no distribution |
| Azure | `404 Web Site not found` on azurewebsites.net |

## Real-World Examples (HackerOne — paid reports)

5 paid reports. Top bounty: $1,000 (Grab — CloudFront CDN subdomain takeover).

| Title | Severity | Bounty | Program | Report |
|-------|----------|--------|---------|--------|
| Subdomain Takeover via insecure CloudFront distribution (cdn.grab.com) | Medium | $1,000 | Grab | [#352869](https://hackerone.com/reports/352869) |
| addons-preview-cdn.mozilla.net takeover via unregistered Fastly domain | Medium | $500 | Mozilla | [#2706358](https://hackerone.com/reports/2706358) |
| Subdomain takeover on firefox.com subdomain | Medium | $500 | Mozilla | [#2899858](https://hackerone.com/reports/2899858) |
| Subdomain takeover of resources.hackerone.com | Low | $500 | HackerOne | [#863551](https://hackerone.com/reports/863551) |
| Subdomain takeover http://accessday.opn.ooo/ | Medium | $50 | Omise | [#1963213](https://hackerone.com/reports/1963213) |

**Key patterns from reports:**
- CDN providers (Fastly, CloudFront) are the most common vector — CDN distributions are frequently created and deleted as infrastructure changes
- Even security-focused programs (HackerOne itself, Mozilla) had dangling subdomains — resources.hackerone.com was taken over via an expired third-party service
- Bounties are consistent at $500 for medium-severity, with $1,000 for CDN/production subdomains with broader impact
- Proof of impact matters: demonstrating cookie scope, CSP bypass, or phishing potential increases severity

## Detection and Defence

| Issue | Fix |
|-------|-----|
| Dangling CNAME | Audit DNS records regularly; remove CNAMEs when cloud resources are deleted |
| Unclaimed S3 bucket name | Apply bucket reservation policy; use unique naming conventions |
| CDN distribution deleted but DNS remains | Automate DNS cleanup as part of infrastructure teardown |
| Cookie scope includes subdomain | Scope cookies to the primary domain only (`Domain=company.com` not `.company.com`) |

## Tools

- `subfinder` — passive subdomain enumeration
- `amass` — active + passive subdomain discovery
- `dnsx` — bulk DNS resolution and CNAME chasing
- `subjack` / `nuclei` (subdomain-takeover templates) — automated dangling CNAME detection
- `can-i-take-over-xyz` (EdOverflow) — reference list of vulnerable service fingerprints
