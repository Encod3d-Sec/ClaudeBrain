# ClaudeBrain Wiki

A living offensive-security reference: 430+ cross-linked technique pages, payload
arsenals, tool references, and cheatsheets. Built in Obsidian and indexed for
semantic search, so hunt skills consult it before attacking.

Pages cross-link with Obsidian `[[wikilinks]]` and a graph map-of-content, clickable inside
Obsidian. On GitHub, browse via the directory links below.

## Techniques

| Domain | Pages | Domain | Pages |
|---|---|---|---|
| [Active Directory](techniques/active-directory/) | 101 | [Cloud](techniques/cloud/) | 51 |
| [Web](techniques/web/) | 67 | [Network](techniques/network/) | 17 |
| [Red Team](techniques/red-team/) | 14 | [Exploit Dev](techniques/exploit-dev/) | 13 |
| [Methodology](techniques/methodology/) | 10 | [OSINT](techniques/osint/) | 7 |
| [Cracking](techniques/cracking/) | 5 | [Mobile / IoT](techniques/mobile-iot/) | 5 |
| [Linux](techniques/linux/) | 4 | [Forensics](techniques/forensics/) | 2 |

## Arsenal

- [Payloads](payloads/) - per-vulnerability-class payload sets (SQLi, XSS, SSRF, SSTI, XXE, IDOR, deserialization, and more)
- [Tools](tools/) - per-tool references (nmap, ffuf, nuclei, httpx, sqlmap, BloodHound, netexec, ...)
- [Cheatsheets](cheatsheets/) - quick-reference command sheets and default-credential tables

## Recent additions (2026 CVE research)

Extracted from public security-research forks (single-source; verify against vendor advisories):

- [Linux kernel rootkits (LKM / ftrace-hooking)](techniques/linux/linux-rootkits.md) - modern 6.x LKM stealth and detection
- Drupal JSON:API PostgreSQL SQLi (CVE-2026-9082) in [SQL Injection](techniques/web/sql-injection.md)
- 2026 kernel LPEs (futex requeue-PI, netfilter IDLETIMER, IPv6 RPL SRH, pidfd FD-theft) in [Kernel Exploitation](techniques/exploit-dev/kernel-exploitation.md)
- WS2025 local NTLM reflection to SYSTEM (CVE-2026-24294) in [Internal NTLM Relay](techniques/active-directory/internal-ntlm-relay.md)
- Chrome / Firefox renderer RCE plus all the above in the [CVE Arsenal](cheatsheets/cve-arsenal.md)

## License

MIT, see [../LICENSE](../LICENSE).
