---
title: "Open Redirect"
type: technique
tags: [h1, open-redirect, phishing, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-21
sources: [h1-scraped-open-redirect, payloadsallthethings-open-redirect]
---

Quick payloads: [[payloads/open-redirect]].

## What it is

A vulnerability where an application accepts a user-controlled URL as a redirect target without validating that it points to an allowed domain, allowing attackers to redirect victims to malicious sites.

## How it works

Applications often redirect users after login, logout, OAuth flows, or link-click tracking using a `next`, `redirect`, `url`, or `return_to` parameter. When the target URL is not validated against an allowlist, an attacker can supply an external URL.

## Attack phases

Exploitation — often chained with phishing, OAuth token theft, or SSRF.

## Methodology

1. Find redirect parameters: `?next=`, `?redirect=`, `?url=`, `?return_to=`, `?returnUrl=`, `?goto=`
2. Test with external URL: `?next=https://evil.com`
3. Try bypasses if blocked: `//evil.com`, `\/\/evil.com`, `https:evil.com`, URL encoding, subdomains (`evil.com.target.com`)
4. Check OAuth `redirect_uri` — open redirect here = token theft
5. Look for redirect in `Location:` headers after POST actions

## Filter Bypass Techniques

- **CRLF injection** to bypass `javascript:` blacklist: `java%0d%0ascript%0d%0a:alert(0)`
- **Using `//`, `\/\/`, `https:`** to bypass `http` or `//` filters: `\/\/google.com/`
- **Null byte** or **Ideographic Full Stop**: `//google%00.com` or `//google%E3%80%82com`
- **Using `@` character**: `http://www.theirsite.com@yoursite.com/`
- **Using `?` character**: `http://www.yoursite.com?http://www.theirsite.com/` (browser translates it to `/?`)
- **Host/Split Unicode Normalization**: `https://evil.c℀.example.com` normalizes to `https://evil.ca/c.example.com`
- **Creating folder as domain**: `http://www.yoursite.com/http://www.theirsite.com/`

## Key payloads / examples

```
?next=https://evil.com
?next=//evil.com
?next=\/\/evil.com
?redirect_uri=https://evil.com%2F@legitimate.com
```

## Real-World Examples (HackerOne — paid reports)

42 paid reports. Top bounty: $2,400 (Internet Bug Bounty — Rails Action Pack CVE). Notable: OAuth `redirect_uri` theft paid $750 at GSA Bounty.

| Title | Severity | Bounty | Program | Report |
|-------|----------|--------|---------|--------|
| Open Redirect in Action Pack (Rails CVE) | Medium | $2,400 | Internet Bug Bounty | [#1865991](https://hackerone.com/reports/1865991) |
| Open Redirect (Rails 6.0.0 < 6.0.3.2) | High | $1,000 | Ruby on Rails | [#904059](https://hackerone.com/reports/904059) |
| Open Redirect in Logout & Login | Medium | $1,000 | Expedia Group | [#1788006](https://hackerone.com/reports/1788006) |
| Instant open redirect in Live preview Web IDE | Low | $1,000 | GitLab | [#437142](https://hackerone.com/reports/437142) |
| Open redirect at inventory.upserve.com | Medium | $1,200 | Upserve | [#469803](https://hackerone.com/reports/469803) |
| Stealing Users OAuth Tokens via redirect_uri | High | $750 | GSA Bounty | [#665651](https://hackerone.com/reports/665651) |
| Chained open redirects via Ideographic Full Stop | Medium | $560 | X / xAI | [#1032610](https://hackerone.com/reports/1032610) |
| Error message acceptance redirects to attacker site | Medium | $560 | X / xAI | [#781673](https://hackerone.com/reports/781673) |
| Open redirect on mobile version (m.vk.com) | Medium | $300 | VK.com | [#456963](https://hackerone.com/reports/456963) |
| Host Header Injection → Open Redirect + Content Spoofing | Medium | $300 | Omise | [#1444675](https://hackerone.com/reports/1444675) |
| Google API key leak leads to Open Redirect | Medium | $300 | Clario | [#1066410](https://hackerone.com/reports/1066410) |
| Session takeover via open protocol redirection | Medium | $200 | Logitech (Streamlabs) | [#1178239](https://hackerone.com/reports/1178239) |
| Event attachments linking to external websites | Medium | $250 | Nextcloud | [#2457588](https://hackerone.com/reports/2457588) |
| Open redirect via prejoin_data parameter | Medium | $250 | Chaturbate | [#400982](https://hackerone.com/reports/400982) |
| Open redirect on "Unsupported browser" warning | Medium | $150 | Nextcloud | [#1977222](https://hackerone.com/reports/1977222) |

**Key patterns from reports:**
- Framework-level CVEs (Rails Action Pack, Rails routing) pay the highest bounties — patch bypasses escalate value further
- OAuth `redirect_uri` open redirects are high-severity because they enable token theft (GSA $750 as high severity)
- Session takeover chains (open redirect + protocol handler abuse) paid $200 at Logitech/Streamlabs
- Unicode/homoglyph bypass (Ideographic Full Stop `。` instead of `.`) defeated Twitter's domain blocklist ($560)
- Host Header Injection as an open redirect vector: `Host: evil.com` causes redirect to attacker domain ($300 at Omise)
- Low-severity bugs on internal/preview endpoints still paid $1,000 at GitLab

## Detection and Defence

| Issue | Fix |
|-------|-----|
| Unvalidated `next`/`url` parameter | Allowlist of allowed redirect destinations; reject external URLs |
| `redirect_uri` in OAuth | Exact-match against pre-registered URIs only |
| Header injection via Host header | Validate `Host` header; use explicit server_name configs |
| Unicode/homoglyph bypass | Normalize URLs to punycode before validation |
| Protocol handler redirect | Block redirects to non-http(s) schemes |

## Tools

- [[burp-suite]] — intercept and modify redirect parameters
- [[ffuf]] — fuzz for redirect parameter names

## Related

- [[ssrf]] (an allowlisted open redirect chains past SSRF host filters)
- [[xss]] (javascript: or data: redirect targets execute script)
- [[oauth-attacks]] (an open redirect on redirect_uri steals OAuth codes and tokens)
