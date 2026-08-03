---
title: "Network Protocol Attacks"
type: technique
tags: [network, smb, snmp, dns, nfs, rpc, ldap, smtp, redis, enumeration, exploitation]
phase: enumeration
date_created: 2026-06-16
date_updated: 2026-07-02
sources: [terrapin-attack]
---

## What it is

Service-specific enumeration and exploitation of common network protocols beyond web: SMB, SNMP, DNS, NFS, RPC, LDAP, SMTP, and exposed data stores (Redis, memcached). Complements [[service-enumeration]] and [[network-service-attacks]] with per-protocol depth.

## How it works

Each protocol exposes its own enumeration surface (shares, OIDs, zone records, exports) and misconfigurations (null sessions, public community strings, open relays, unauthenticated data stores) that leak data or grant access.

## Attack phases
Enumeration -> exploitation.

## Prerequisites
- Network reach to the port. Identify the service first (`nmap -sV -sC -p<port> <target>`).

## Methodology

### SMB (139/445)
```bash
nxc smb <t> -u '' -p '' --shares --users --pass-pol     # null session ([[netexec]])
smbclient -L //<t>/ -N;  smbclient //<t>/share -N
enum4linux-ng -A <t>
nmap --script "smb-vuln-*" -p445 <t>                    # MS17-010 etc
```
Anonymous shares, writable shares (drop payload), SMB signing off -> relay -> [[active-directory]].

### SNMP (161/udp)
```bash
snmpwalk -v2c -c public <t>;  onesixtyone -c communities.txt <t>
snmpbulkwalk -v2c -c public <t> 1.3.6.1.2.1.25.4.2.1.2   # running processes
```
Public/private community strings leak processes, ARP/routes, users, and sometimes config with creds.

### DNS (53)
```bash
dig axfr @<ns> <domain>                                 # zone transfer
dnsenum <domain>;  dnsrecon -d <domain> -t std,brt
```
Zone transfer dumps all records; subdomain brute reveals internal hosts; check for dynamic-update and cache snooping.

### NFS (2049)
```bash
showmount -e <t>                                        # exports
mount -t nfs <t>:/export /mnt/nfs -o nolock
# no_root_squash + UID spoof -> write SUID root binary
```

### RPC / rpcbind (111/135)
```bash
rpcinfo -p <t>;  rpcclient -U '' -N <t> -c "enumdomusers; querydispinfo"
```

### LDAP (389/636)
```bash
ldapsearch -x -H ldap://<t> -b "dc=corp,dc=local"       # anonymous bind
nxc ldap <t> -u '' -p '' --users
```

### SMTP (25/587)
```bash
smtp-user-enum -M VRFY -U users.txt -t <t>              # user enumeration
swaks --to a@b --server <t>                             # test open relay
```

### Data stores (often unauthenticated)
```bash
redis-cli -h <t>                                        # then: config get dir; module load; SSH key write / webshell
nc <t> 11211 -> stats / cachedump                       # memcached
mongo --host <t> --eval "db.adminCommand('listDatabases')"
```

### SSH (22): Terrapin prefix truncation (CVE-2023-48795)

Terrapin is a MITM prefix-truncation attack on the SSH transport. During the handshake the attacker injects `SSH_MSG_IGNORE` packets in the unencrypted phase to pre-offset the sequence numbers, then deletes packets from the start of the secure channel; the sequence counters still line up, so the truncation passes the integrity check undetected. This lets the attacker strip the server's `SSH_MSG_EXT_INFO` (RFC 8308) extension-negotiation message, silently downgrading capabilities (for example weakening RSA public-key auth signature negotiation, or disabling OpenSSH 9.5 keystroke-timing obfuscation).

Only certain modes are exploitable because they bind the handshake sequence numbers to the session:
- `chacha20-poly1305@openssh.com` (directly exploitable).
- Any `*-cbc` cipher combined with an Encrypt-then-MAC `*-etm@openssh.com` MAC.
- CTR + EtM is theoretically affected but not practically exploitable.

Requires an active MITM on the network path; it is not a remote pre-auth exploit on its own.

Fix is "strict kex" (strict key exchange): both ends reset the sequence number to zero after the key exchange completes and refuse non-essential messages (like `SSH_MSG_IGNORE`) during the handshake, removing the injection primitive. Both client and server must support strict kex; a patched server still downgrades for an unpatched client. Advertised via the `kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com` pseudo-algorithms in the KEXINIT.

Detect vulnerable servers with the Terrapin scanner (Go, RUB-NDS). It fingerprints the offered ciphers/MACs and strict-kex support without performing a full handshake or the actual attack:

```bash
# https://github.com/RUB-NDS/Terrapin-Scanner
terrapin-scanner --connect <t>:22
# vulnerable if a chacha20-poly1305 or *-cbc + *-etm mode is offered AND strict kex is absent
```

Remediate by upgrading OpenSSH (>= 9.6) or the SSH stack, or by disabling the affected algorithms server-side until strict kex is in place:

```
Ciphers -chacha20-poly1305@openssh.com
MACs -*-etm@openssh.com
```

## Bypasses and variants
- UDP services (SNMP/DNS/NFS) need `-sU` and are easy to miss in default scans.
- Redis -> RCE via `CONFIG SET dir`/`dbfilename` to write a webshell/SSH key/cron, or `MODULE LOAD`.

## Detection and defence
Disable null sessions/anonymous binds, restrict SNMP to v3 + non-default community, deny zone transfers, `root_squash` on NFS, authenticate data stores + bind to localhost, firewall UDP services.

## Tools
[[netexec]], `nmap` NSE, `snmpwalk`/`onesixtyone`, `dig`/`dnsrecon`, `showmount`, `rpcclient`, `ldapsearch`, `smtp-user-enum`/`swaks`, `redis-cli`. See [[service-enumeration]], [[network-service-attacks]], [[pivoting-tunneling]].

## Sources
