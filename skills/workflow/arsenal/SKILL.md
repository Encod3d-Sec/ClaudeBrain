---
name: arsenal
description: Wiki-first "what do I use" lookup - pick the automated TOOL (wiki/tools/), then the PAYLOAD/technique (wiki/payloads/ + wiki/cheatsheets/), for a surface/service/vuln-class BEFORE hand-rolling or working from memory. Use for "tool for <service>", "automated tools for web/<service>", "what should I run on <surface>", "which tool for <X>", "payloads for <X>", "payload arsenal", "cheatsheet for <X>", "how do I exploit <tech/class>", "exploit/attack chain for <X>", "arsenal", any SSRF/XSS/SQLi/SSTI/LFI/JWT/XXE/IDOR/NoSQL/deserialization/CSRF/CORS/CRLF/GraphQL/smuggling/web-cache/OAuth/SAML/MFA/crypto/LDAP/XPath/WebAuthn/file-upload/IMDS/prompt-injection/Modbus ask, plus "privesc arsenal", "CVE arsenal", "default creds", "nuclei templates", "sqlmap/hydra/nmap/bloodhound", "password attacks".
---

# Arsenal

Wiki-first router. On any surface/service/vuln, get the documented TOOL and PAYLOAD from the wiki
BEFORE hand-rolling or recalling from memory. The lookup itself is delegated to the fast parallel
engine:

**-> `Skill(wiki-arsenal)`** - quick by default (one qmd search across all four areas, cheap, fire
it constantly); say "deep" / "full arsenal" for the 4-parallel-agent synthesized + cached card. It
covers wiki/tools + wiki/payloads + wiki/techniques + wiki/cheatsheets and returns the tool +
payload + technique + commands.

The tables below are the at-a-glance index of what `wiki-arsenal` pulls from - use them to
sanity-check its result, not as a substitute for the lookup. Order: automated tool -> technique -> capture.

## 1. Tool first (from `wiki/tools/` - don't improvise)
A service/surface is fingerprinted -> reach for the tool we already document for it. Have a tool
for the service? Use it; do not hand-roll a curl/socket loop. `ls wiki/tools/` for all 64.

| Surface / service | Automated tools (`wiki/tools/<name>.md`) |
|---|---|
| Web HTTP(S) | httpx, whatweb, nikto -> ffuf/feroxbuster/gobuster (content) -> katana/gau (crawl) -> arjun (params) -> nuclei (CVE/misconfig) -> dalfox (XSS) -> wpscan (WP); gowitness, burp-suite/burp-mcp |
| Ports / host | nmap, rustscan, naabu |
| DNS / subdomains | subfinder, amass, dnsx, gau |
| SMB / Windows / AD | netexec, responder, impacket, bloodhound/powerview, kerbrute, certipy/rubeus, evil-winrm |
| Login / creds | hydra, medusa (brute) -> hashcat, john (crack) -> jwt_tool (JWT) -> swaks (SMTP) |
| Post-shell privesc | pspy + linpeas/peass (ALWAYS, first) |
| Pivot / tunnel | chisel, ligolo-ng |
| Cloud | pacu, scoutsuite, roadtools, trivy |
| Binary / RE / pwn | ghidra, radare2, gdb-gef, pwntools, angr, binwalk, jadx, apktool, frida |
| Secrets / SAST / forensics | trufflehog, trivy, semgrep, codeql, volatility, tshark |

Read the tool page for the exact flags before running; no page -> `qmd_query`/`Skill(wiki)`.

## 2. Then technique / payload (`wiki/payloads/` + `wiki/cheatsheets/`)
- **Vuln class -> `wiki/payloads/<class>.md`**: sqli, xss, ssrf, ssti, xxe, idor, nosql, jwt,
  deserialization, command-injection, lfi-path-traversal, csrf, cors, crlf, graphql, api,
  auth-bypass, session, race-conditions, prototype-pollution, open-redirect, host-header,
  smuggling, web-cache, oauth-saml, mfa-bypass, crypto, ldap, xpath, webauthn-passkey,
  file-upload, imds-cloud-metadata, llm-prompt-injection, modbus, cicd.
- **Exploitation / privesc / chains -> `wiki/cheatsheets/*`**: privesc-exploit-arsenal,
  cve-arsenal, attack-chains, linux-privesc / windows-privesc, default-credentials,
  nuclei-arsenal, sqlmap, password-attacks.

Read the matching page(s) BEFORE hand-rolling a payload/exploit. The full class-specific
methodology lives in the matching `hunt-*` skill - hand off to it.

## 3. Capture the moment
Something lands (a confirmed vuln, creds, a shell, a flag) -> capture it AS it lands, not at
the end. Capture is manual and live: run `capture.sh` (or `Skill(screenshot)`) into `poc/`
the moment a flag/shell lands, for the deliberate exploited/authed state so it can be
manually reviewed.
