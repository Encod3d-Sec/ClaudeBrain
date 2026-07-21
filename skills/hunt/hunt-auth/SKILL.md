---
name: hunt-auth
description: Auth bypass and ATO hunting - legacy protocol matrix (XMLRPC, SharePoint /_vti_bin/, EWS, Citrix, etc.), JWT manipulation, password reset poisoning, SAML auth bypass, session fixation. Wiki-first, FIND schema output.
---

# Hunt: Auth Bypass & Account Takeover

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "authentication bypass account takeover" via wiki-search MCP -> read matching technique page if found.
```
Apply known legacy endpoint patterns and JWT bypass techniques already documented. Payload arsenals: `wiki/payloads/{auth-bypass,csrf,mfa-bypass,session,crypto}.md` (tokens: [[jwt]], `oauth-saml`).


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip paths already marked exhausted

## Legacy Protocol Matrix (Probe First on Any Custom-Branded Login)

When a target has a custom/branded login UI, ALWAYS probe the platform's legacy protocol endpoints. These often accept native credentials with NO rate limit, NO MFA, NO CAPTCHA.

| Target tech | Legacy endpoint | Bypass surface |
|---|---|---|
| WordPress | `/xmlrpc.php` | Native WP creds; bypasses SSO, MFA, IP-allow on /wp-login.php |
| SharePoint | `/_vti_bin/Authentication.asmx` | SOAP Login op; FedAuth cookie returned; no rate limit observed |
| SharePoint REST | `/_api/contextinfo` (POST) | Anonymous FormDigest issuance |
| Atlassian Jira/Confluence | `/rest/auth/1/session` | Native creds accepted even when Atlassian Access SSO enforced on UI |
| Exchange / OWA | `/EWS/Exchange.asmx`, `/Microsoft-Server-ActiveSync` | NTLM/Basic; bypasses OWA MFA restrictions |
| Citrix NetScaler | `/vpn/index.html`, `/cgi/login` | Native AD credentials independent of MFA wrappers |
| F5 BIG-IP | `/mgmt/tm/util/bash`, `/tmui/login.jsp` | Native admin creds |
| Spring Boot | `/actuator/*` | Sometimes anonymously enumerable |
| Jenkins | `/jnlpJars/jenkins-cli.jar`, `/script` | API tokens + native auth |
| Apache Tomcat | `/manager/html` | Native Tomcat realm creds |
| Drupal | `/user/login?_format=json` | JSON POST accepts native passwords independent of SSO middleware |
| Generic ASP.NET | `*.asmx?WSDL`, `trace.axd`, `elmah.axd` | Each ASMX may take creds independently |

**How to use:**
1. Identify tech stack from headers/paths
2. Probe legacy endpoint anonymously (confirm reachable, not 403/404)
3. Test with synthetic credentials - confirm differential (success vs failure)
4. Verify NO rate limit: burst 10 requests at same user, confirm uniform timing
5. Report as Critical/High if unlimited credential brute-force endpoint confirmed

## JWT Attacks
```bash
# 1. Decode JWT
echo "HEADER.PAYLOAD.SIGNATURE" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# 2. Test none algorithm
# Change "alg":"RS256" -> "alg":"none", remove signature
eyJhbGciOiJub25lIn0.PAYLOAD.

# 3. HS256/RS256 key confusion
# If RS256, try signing with public key as HS256 secret
```

## ATO Attack Paths (Priority Order)
1. **Password reset poisoning**: `POST /forgot-password` with `X-Forwarded-Host: attacker.com` -> reset link sent to attacker
2. **Reset token in Referer leak**: reset page loads external analytics -> full Referer with token leaked
3. **Email change without re-auth**: `PUT /api/user/email {"new_email": "attacker@evil.com"}` without current_password
4. **Session fixation**: set session cookie before auth -> persists after login
5. **IDOR -> ATO chain**: `PATCH /api/users/{victim_uid}` with attacker session -> change victim email -> reset password

## Methodology
1. Map all authentication entry points (main, admin, API, partner, mobile)
2. Identify auth mechanism per entry (forms, SAML, OAuth, API key, session)
3. Test legacy endpoints per tech stack (use matrix above)
4. Probe XMLRPC if WordPress: `system.listMethods`, `wp.getUsersBlogs`
5. Test JWT if present: none algorithm, key confusion, weak secret
6. Test password reset: host header injection, token in Referer, token reuse after expiry
7. Test email change: no re-auth, no confirmation
8. Verify impact: demonstrate full ATO on test account B from attacker session A
9. **Distill to wiki (when confirmed):** if the finding is a reusable legacy-endpoint bypass or JWT variant, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/authentication-attacks.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output

If auth bypass or ATO confirmed:
```
Create Vulns/Research/FIND-XXX-CRITICAL-auth-bypass-<host>.md (if no auth needed)
Create Vulns/Research/FIND-XXX-HIGH-ato-<host>.md (if requires one click)
Add row to Vuln-index.md under CRITICAL or HIGH
```

If legacy endpoint found but no creds to test:
```
Create Vulns/Research/FIND-XXX-MEDIUM-legacy-auth-endpoint-<host>.md
Document: endpoint reachable, accepts native creds, no rate limit, awaiting cred list
```

If path exhausted:
```
Append to Deadends.md: - [ ] Auth bypass on <host> -- legacy endpoints 404, JWT RS256 key confusion failed, reset tokens expire
```

Report: Status + files created.
