---
name: hunt-upload
description: File upload attack hunting - extension/content-type/magic-byte bypass to web-shell RCE, path traversal in filename, SVG/XML XSS, zip slip, and pixel-flood DoS. Wiki-first, FIND schema output.
---

# Hunt: File Upload

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "file upload webshell extension content-type magic-byte bypass SVG XXE zip slip path traversal" via wiki-search MCP
```

Hub: [[web-moc]] (live index). Primary page: [[file-upload]]. Payload arsenal: `wiki/payloads/file-upload.md`.
Anchors: [[path-traversal-lfi]].

## Attack surface

Rank the sinks first - not every upload reaches code:

- **Avatar / profile / logo / signature fields** - most common; frequently re-encoded, so check whether the original bytes are served back.
- **Document / CSV / XML import** - parser sinks (XXE, formula injection, zip).
- **Ticket / message attachments** - often served under the original name and type from a reachable path.
- **Image-processing** (thumbnails -> ImageMagick/Ghostscript), SVG/PDF render, EXIF parsers - the processor is the bug, not the store.
- **Firmware / plugin / theme upload** - direct code load; highest value when present.

Then attack in layers, cheapest first: **extension -> content-type -> magic-byte -> parser/render.**

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
5. **SVG / XML:** SVG with `<script>` -> stored XSS ([[xss]]); SVG/XML with external entity -> [[xxe]] (file read/SSRF).
6. **Archive:** zip-slip (`../` paths inside zip) on extract; symlink in archive -> read host files.
7. **Image processing:** ImageMagick/Ghostscript (ImageTragick CVE-2016-3714), pixel-flood DoS, EXIF payload executed by a downstream parser.
8. **Confirm by execution, through Burp.** Request the uploaded shell in **Burp Repeater** (operator visibility) and run a command (`?cmd=id`); OOB callback if blind. For traversal, fetch the written/read target back from the path you claimed it hit.
9. **Distill (confirmed, generic):** per hunt-core, `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/file-upload.md`.

## Evasion (when a layer rejects)
Double extension (`shell.php.jpg` / `shell.jpg.php`), null byte (`shell.php%00.jpg`), content-type spoof (`Content-Type: image/png` on a script), magic-byte prefix (`GIF89a;` + payload), and case variation (`.pHp`, `.PHtml`). Combine them - a single-layer allowlist rarely survives extension + content-type + magic-byte applied together.

## Chaining
- **Upload -> web-shell RCE:** once a shell executes, hand off `hunt-rce` for post-exploitation and CVE-specific escalation.
- **SVG/HTML -> stored XSS:** hand off `hunt-xss` (marker discipline, blind-XSS beacon for a stored context).
- **SVG/XML/DOCX -> XXE:** hand off `hunt-injection` (OOB-mandatory for blind XXE).

## Confirmation gate

**NOT confirmation:** the upload was accepted; a `200` or a returned file URL; the file shows up in a listing; a stored path you have not fetched back; a script uploaded but never requested; a traversal filename accepted with nothing actually read or written outside the upload dir.

**IS confirmation:** the uploaded file **executed as code** - fetch it back and it runs your command (`?cmd=id` returns output) or fires an OOB callback when blind; or the traversal demonstrably **wrote or read outside the upload dir**, proven by fetching that target back. SVG/XML: the script fires in a victim context, or the external entity returns file contents / an OOB hit. Reproduce in a clean session.

## Severity
CRITICAL if code execution; HIGH if stored XSS / XXE / arbitrary file write to a sensitive path; MEDIUM if upload of a dangerous type with no execution path proven.

## Deadends
```
Append: - [ ] upload <host> <endpoint> -- ext+CT+magic+traversal all blocked; files re-encoded + served from CDN no-exec
```
Record which layers you cleared and which held, so the next pass does not retry them.
