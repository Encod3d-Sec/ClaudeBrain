---
title: Hash - Pass The Key
type: technique
tags: [active-directory, kerberos, lateral-movement, reference-import, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Hash - Pass The Key

## What it is

Pass The Key allows attackers to gain access to systems by using a valid session key instead of the user's password or NTLM hash. This technique is related to other credential-based attacks like Pass The Hash (PTH) and Pass The Ticket (PTT) but specifically uses session keys to authenticate.

## How it works

Pass The Key uses Kerberos encryption keys (AES128, AES256, or RC4/NTLM) extracted from LSASS memory to request a TGT without knowing the account's plaintext password. Unlike Pass-the-Hash, which uses NTLM, PTK operates entirely within the Kerberos protocol, making it less detectable by solutions that focus on NTLM authentication anomalies. The AES keys are extracted from LSASS by Mimikatz (`sekurlsa::ekeys`) and used with `sekurlsa::pth` or Impacket's `getTGT.py` to obtain a valid ticket for the targeted account.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

Pass The Key allows attackers to gain access to systems by using a valid session key instead of the user's password or NTLM hash. This technique is related to other credential-based attacks like Pass The Hash (PTH) and Pass The Ticket (PTT) but specifically uses session keys to authenticate.

Pre-authentication requires the requesting user to provide a secret key, which is derived from their password and may use encryption algorithms such as DES, RC4, AES128, or AES256.

* **RC4**: ARCFOUR-HMAC-MD5 (23), in this format, this is the NTLM hash, go to **Pass The Hash** to use it directly and **Over Pass The Hash** page to request a TGT from it.
* **DES**: DES3-CBC-SHA1 (16), should not be used anymore and have been deprecated since 2018 ([RFC 8429](https://www.rfc-editor.org/rfc/rfc8429)).
* **AES128**: AES128-CTS-HMAC-SHA1-96 (17), both AES encryption algorithms can be used with Impacket and Rubeus tools.
* **AES256**: AES256-CTS-HMAC-SHA1-96 (18)

In the past, there were more encryptions methods, that have now been deprecated.

| enctype                    | weak?| krb5   | Windows |
| -------------------------- | ---- | ------ | ------- |  
| des-cbc-crc                | weak | <1.18  | >=2000  |
| des-cbc-md4                | weak | <1.18  | ?       |
| des-cbc-md5                | weak | <1.18  | >=2000  |
| des3-cbc-sha1              |    | >=1.1  | none    |
| arcfour-hmac               |    | >=1.3  | >=2000  |
| arcfour-hmac-exp           | weak | >=1.3  | >=2000  |
| aes128-cts-hmac-sha1-96    |    | >=1.3  | >=Vista |
| aes256-cts-hmac-sha1-96  |      | >=1.3  | >=Vista |
| aes128-cts-hmac-sha256-128 |    | >=1.15 | none    |
| aes256-cts-hmac-sha384-192 |    | >=1.15 | none    |
| camellia128-cts-cmac    |      | >=1.9  | none    |
| camellia256-cts-cmac    |      | >=1.9  | none    |

Microsoft Windows releases Windows 7 and later disable single-DES enctypes by default.

Either use the AES key to generate a ticket with `ticketer`, or request a new TGT using `getTGT.py` script from Impacket.

## Generate a new ticket

* [fortra/impacket/ticketer.py](https://github.com/fortra/impacket/blob/master/examples/ticketer.py)

```powershell
impacket-ticketer -aesKey 2ef70e1ff0d18df08df04f272df3f9f93b707e89bdefb95039cddbadb7c6c574 -domain lab.local Administrator -domain-sid S-1-5-21-2218639424-46377867-3078535060
```

## Request a TGT

* [fortra/impacket/getTGT.py](https://github.com/fortra/impacket/blob/master/examples/getTGT.py)

```powershell
impacket-getTGT -aesKey 2ef70e1ff0d18df08df04f272df3f9f93b707e89bdefb95039cddbadb7c6c574 lab.local
```

* [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

```powershell
.\Rubeus.exe asktgt /user:Administrator /aes128 bc09f84dcb4eabccb981a9f265035a72 /ptt
.\Rubeus.exe asktgt /user:Administrator /aes256:2ef70e1ff0d18df08df04f272df3f9f93b707e89bdefb95039cddbadb7c6c574 /opsec /ptt
```

## References

* [MIT Kerberos Documentation - Encryption types](https://web.mit.edu/kerberos/krb5-1.18/doc/admin/enctypes.html)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

- [[impacket]]
- [[mimikatz]]
- Also uses (no dedicated page yet): Rubeus

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
