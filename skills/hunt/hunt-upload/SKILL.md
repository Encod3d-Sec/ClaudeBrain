---
name: hunt-upload
description: File upload attack hunting - extension/content-type/magic-byte bypass to web-shell RCE, path traversal in filename, SVG/XML XSS, zip slip, and pixel-flood DoS. Wiki-first, FIND schema output.
---

# Hunt: File Upload

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "file upload bypass web shell" via wiki-search MCP -> read matching page.
```
Core page: [[file-upload]]. RCE sink overlaps [[os-command-injection]]; SVG overlaps [[xss]]. Payload arsenal: `wiki/payloads/file-upload.md`.

**Self-heal:** wiki query empty -> create stub `wiki/techniques/web/file-upload.md` before proceeding.

## Scope Check
- Confirm target in scope. Identify where uploads land (web-root? CDN? processed?) and how they're served back. Read `Deadends.md`.

## Attack Surface Signals
Avatar/profile pictures, document/import, ticket attachments, CSV/XML import, image-processing (thumbnails -> ImageMagick), SVG/PDF render, firmware/plugin upload, signature/logo fields.

## Methodology
1. **Baseline:** upload a valid file; note stored path, returned URL, filename transformation, and whether it is reachable + executed by the server.
2. **Extension bypass:**
```
shell.php  shell.phtml  shell.php5  shell.phar  shell.pHp
shell.php.jpg   shell.jpg.php   shell.php%00.jpg   shell.php;.jpg
shell.php/   shell.php....   (trailing dot/space on Windows)
.htaccess  ->  AddType application/x-httpd-php .jpg   (then upload .jpg shell)
web.config (IIS)   .jsp/.jspx/.war (Java)   .asp/.aspx (IIS)
```
3. **Content-Type / magic-byte bypass:** set `Content-Type: image/png`; prepend real magic bytes (`GIF89a;`, `\xFF\xD8\xFF` JPEG, `%PDF-`) before the payload; polyglot (valid image + PHP).
4. **Path traversal in filename:** `filename="../../../../var/www/html/shell.php"` to escape the upload dir / overwrite files.
5. **SVG / XML:** SVG with `<script>` -> stored XSS; SVG/XML with external entity -> [[xxe]] (file read/SSRF).
6. **Archive:** zip-slip (`../` paths inside zip) on extract; symlink in archive -> read host files.
7. **Image processing:** ImageMagick/Ghostscript (ImageTragick CVE-2016-3714), pixel-flood DoS, EXIF payload executed by a downstream parser.
8. **Confirm RCE:** request the uploaded shell and execute (`?cmd=id`); OOB callback if blind.
9. **Distill to wiki (when confirmed):** if the finding is a reusable extension or parser bypass, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/file-upload.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed:
```
Create Vulns/Research/FIND-XXX-CRITICAL-upload-rce-<host>.md      (web shell executes)
Create Vulns/Research/FIND-XXX-HIGH-stored-xss-svg-<host>.md      (SVG XSS)
Add row to Vuln-index.md: | FIND-XXX | upload -> web shell | host | CONFIRMED |
```
Severity: CRITICAL if code execution; HIGH if stored XSS / XXE / arbitrary file write to sensitive path; MEDIUM if upload of dangerous type with no execution path proven.

Exhausted (server stores outside web-root / renames to random / re-encodes images / strict allowlist, all bypasses fail):
```
Append to Deadends.md: - [ ] upload <host> -- ext+CT+magic+traversal all blocked; files re-encoded + served from CDN no-exec
```

Report: Status + files created.
