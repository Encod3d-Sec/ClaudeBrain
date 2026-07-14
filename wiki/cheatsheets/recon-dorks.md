---
title: "Recon Dorks (Shodan / Censys / Google / GitHub)"
type: cheatsheet
tags: [cheatsheet, recon, osint, dorks, shodan, attack-surface]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

# Recon Dorks

Find the exposed + vulnerable target, then jump to [[cve-arsenal]] to exploit. Scope-gate everything (only query/touch in-scope assets). Pairs with the `wiki-recon` skill.

## Shodan - find vulnerable products (-> CVE arsenal)
```
http.title:"Outlook"  OR  http.favicon.hash:-1957161625        # OWA/Exchange
http.html:"Citrix" port:443  OR  http.title:"NetScaler"         # Citrix (Bleed/CVE-2023-3519)
"FortiGate" port:443  OR  http.title:"FortiGate"                # Fortinet SSL-VPN
http.title:"Ivanti Connect Secure"  OR  "Pulse Secure"          # Ivanti
http.component:"Atlassian Confluence"                           # Confluence OGNL
http.title:"Dashboard [Jenkins]"  OR  X-Jenkins                 # Jenkins
http.title:"GitLab"  OR  http.favicon.hash:516963061            # GitLab
product:"MOVEit"  OR  http.title:"MOVEit"                       # MOVEit Transfer
http.title:"vSphere"  OR  product:"VMware vCenter"              # vCenter
"Server: ColdFusion"  OR  http.component:"Adobe ColdFusion"
http.title:"ScreenConnect"  OR  product:"ConnectWise"
org:"TARGET" net:"x.x.x.x/24" ssl.cert.subject.cn:"*.target.com"   # scope your target
```
Generic exposure:
```
"default password" 200            mongodb "authentication: disabled"
"X-Elastic-Product: Elasticsearch" port:9200      "Redis" -auth port:6379
"Docker" port:2375                screenshot.label:"login"   has_screenshot:true
"X-Jenkins" "Set-Cookie: JSESSIONID"   "MikroTik"   title:"GLPI"   "phpMyAdmin"
```

## Censys / FOFA
```
# Censys
services.tls.certificates.leaf_data.subject.common_name: "*.target.com"
services.software.product: "Confluence"
# FOFA
app="Atlassian-Confluence"   title="Citrix Gateway"   header="X-Jenkins"
cert="target.com" && country="US"
```

## Google dorks
```
site:target.com -www                                   # subdomains
site:target.com ext:php | ext:asp | ext:jsp            # tech/endpoints
site:target.com inurl:admin | inurl:login | intitle:"index of"
site:target.com ext:sql | ext:bak | ext:log | ext:env | ext:config
intitle:"index of" "parent directory" site:target.com
"target" "confidential" ext:pdf | ext:xls | ext:doc    # sensitive docs
inurl:"/server-status" | inurl:"/.git" | inurl:"/.env" site:target.com
filetype:reg reg HKEY_CURRENT_USER intext:password
intitle:"Dashboard [Jenkins]"   inurl:"/wp-content/" "wp-config"
```

## GitHub dorks (secrets / internal intel)
```
org:TARGET   "target.com" password   "target.com" api_key   "internal.target.com"
filename:.env DB_PASSWORD            filename:.npmrc _auth   filename:.dockercfg auth
filename:credentials aws_access_key_id    filename:id_rsa    extension:pem private
"target" AKIA   "target" "BEGIN RSA PRIVATE KEY"   "xoxb-" (slack)   "ghp_" (github pat)
# tools: trufflehog github --org=TARGET ;  gitleaks ;  github-dorks ;  gitrob
```
See [[git-exposure]], [[secret-hunting]].

## Cloud bucket / asset discovery
```
# S3
target.s3.amazonaws.com   s3://target-{dev,prod,backup,assets,logs}   (cloud_enum / s3scanner)
site:s3.amazonaws.com target   site:.blob.core.windows.net target   site:storage.googleapis.com target
cloud_enum -k target -k target-corp        # AWS+Azure+GCP public assets
# cert transparency for subdomains:
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

## Pipeline
`subfinder -> httpx -td -> match product here / Shodan -> [[cve-arsenal]] -> nuclei -tags cve,kev`. Tools: [[subfinder]], [[httpx]], [[nuclei]], [[gowitness]].
