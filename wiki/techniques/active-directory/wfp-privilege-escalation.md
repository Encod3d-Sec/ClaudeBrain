---
title: "WFP Privilege Escalation (NoFilter)"
type: technique
tags: [edr-bypass, ipsec, kernel, lateral-movement, post-exploitation, privilege-escalation, token-theft, windows]
phase: post-exploitation
date_created: 2026-05-12
date_updated: 2026-05-12
sources: [research-nofilter-deepinstinct]
---

# WFP Privilege Escalation (NoFilter)

## What it is

**Windows Filtering Platform (WFP)** is a kernel-level packet-filtering framework built into Windows. The NoFilter technique exploits undocumented WFP internals — specifically the `WfpAle` kernel device and its LUID-indexed token hash table (`gAleMasterHashTable`) — to steal SYSTEM tokens and escalate privileges while bypassing user-mode EDR hooks.

Microsoft confirmed this behaviour is by design; no CVE was issued.

## How it works

The attack chain flows through four layers:

```
FWPUCLNT.DLL  →  BFE.DLL (svchost.exe)  →  tcpip.sys  →  gAleMasterHashTable
  (user API)       (RPC broker)              (kernel driver)    (token store)
```

When a service establishes a connection matching an active IPSec policy, `tcpip.sys` automatically calls `WfpAleProcessTokenReference` and stores the service's token in `gAleMasterHashTable` indexed by LUID. The kernel device `\\\\.\\WfpAle` exposes direct IOCTL access to this table — bypassing BFE's access-check RPC layer entirely.

The device's security descriptor prevents *creating* new handles but not *duplicating* existing ones. The BFE service (running as SYSTEM) holds a permanent open handle to `WfpAle`; duplicating it requires only `PROCESS_DUP_HANDLE` on BFE.

## Attack phases

- **Post-exploitation** — requires local admin or debug privileges (SeDebugPrivilege) to duplicate BFE's handle

## Prerequisites

- Local administrator or `SeDebugPrivilege` on the target host
- Windows 10 / Server 2016 or later (WFP with IPSec support)
- At least one injectable service running (Print Spooler, LSM, Winmgmt, Schedule, OneSyncSvc)

## Methodology

### Attack 1: Direct Token Duplication via WfpAle device

Extracts a SYSTEM token directly from `gAleMasterHashTable` without triggering any service connection.

1. Obtain a handle to `\\\\.\\WfpAle` by duplicating BFE's handle with `DuplicateHandle` (requires `PROCESS_DUP_HANDLE` on BFE, i.e. debug privileges)
2. Send IOCTL `0x128000` (`WfpAleProcessTokenReference`) with the target service PID (e.g. LSM, Winmgmt, Schedule) — kernel attaches to that process and calls `DuplicateToken` internally
3. Receive a LUID in the response
4. Send IOCTL `0x124008` (`WfpAleQueryTokenById`) with the returned LUID — receive a token handle with `TOKEN_DUPLICATE`
5. Call `DuplicateToken` again locally to upgrade to `TOKEN_ALL_ACCESS`
6. Use `ImpersonateLoggedOnUser` / `CreateProcessWithTokenW` to spawn a SYSTEM process

**Key advantage:** No `DuplicateHandle`/`DuplicateToken` WinAPI calls in user-space — EDR hooks on those APIs are bypassed. All token manipulation happens in kernel context.

### Attack 2: IPSec-triggered token insertion (Print Spooler)

Forces a privileged service to insert its token by triggering a localhost connection under an active IPSec policy.

1. Create an IPSec policy via WFP API for localhost with a pre-shared key:
```python
# Documented Microsoft example — configure transport-mode IPSec for 127.0.0.1
# Uses FwpmEngineOpen0, FwpmFilterAdd0, FwpmProviderContextAdd0
```
2. Call `RpcOpenPrinter` on the Spooler service with printer name `\\\\127.0.0.1` — Spooler initiates a connection matching the policy
3. On connection, `WfpAleInsertTokenInformationByUserTokenIdIfNeeded` inserts the Spooler's SYSTEM token
4. Brute-force the LUID in range `1..0x1000` via repeated `WfpAleQueryTokenById` (IOCTL `0x124008`)
5. Duplicate retrieved token and spawn SYSTEM process

**Key advantage:** Configuring IPSec policies is a legitimate sysadmin action; no anomalous process launches.

### Attack 3: User token extraction via OneSyncSvc (lateral movement between sessions)

Extracts tokens belonging to *other logged-in users* for cross-session lateral movement.

1. Configure IPSec policy (same as Attack 2)
2. Enumerate services — identify the `OneSyncSvc` PID for the target user session
3. Enumerate ALPC ports to find the unique port opened by that OneSyncSvc instance
4. Spin up a listener on `127.0.0.1:443`
5. Call RPC method `AccountsMgmtRpcDiscoverExchangeServerAuthType` (interface `923c9623-db7f-4b34-9e6d-e86580f8ca2a`) with parameter `"user@127.0.0.1"` — forces OneSyncSvc to connect to your listener
6. While the connection is active, the user's token is in `gAleMasterHashTable`
7. Brute-force LUID (`1..0x1000`), retrieve and duplicate token
8. `CreateProcessWithTokenW` spawns a process in the target user's context

**Key advantage:** `OneSyncSvc` and `SyncController.dll` have never been used in offensive tooling before; EDR behavioural baselines won't flag it.

## Key payloads / examples

### Device IO control codes (tcpip.sys WfpAle device)

| IOCTL | Function | Purpose |
|---|---|---|
| `0x124008` | `WfpAleQueryTokenById` | Retrieve token from table by LUID |
| `0x124018` | `WfpAleProcessEndpointPropertiesQuery` | Query endpoint properties |
| `0x12401E` | `WfpAleProcessEndpointEnumIoctl` | Create enum handle |
| `0x128000` | `WfpAleProcessTokenReference` | Insert token for a given PID |
| `0x128004` | `WfpAleReleaseTokenInformationById` | Release token entry |
| `0x128010` | `WfpAleProcessExplicitCredentialQuery` | Query stored credentials |

### Using NoFilter tool

```bash
# Attack 1: direct token duplication from a specific service
NoFilter.exe --method direct --service LSM

# Attack 2: IPSec-triggered via Print Spooler
NoFilter.exe --method ipsec --service Spooler

# Attack 3: cross-session user token (target session ID)
NoFilter.exe --method onesync --session 2
```

### LUID brute-force loop (pseudocode)

```python
for luid in range(1, 0x1001):
    result = DeviceIoControl(wfpale_handle, 0x124008, luid, ...)
    if result == SUCCESS:
        # token found — duplicate it
        break
```

### Undocumented RPC methods exposed by BFE

```
BfeRpcOpenToken(engineHandle, modifiedId, desiredAccess)     → wraps WfpAleQueryTokenById
BfeRpcAleExplicitCredentialsQuery(...)                       → blocked for admin; use IOCTL instead
FwpsOpenToken0(engineHandle, modifiedId, desiredAccess)      → FWPUCLNT.DLL wrapper
```

## Bypasses and variants

**EDR API-hook bypass:** Direct IOCTL to `\\\\.\\WfpAle` skips all user-mode API hooks on `DuplicateHandle`, `DuplicateToken`, `OpenProcess` — the token never appears in user-space WinAPI calls.

**BFE access-check bypass:** `BfeRpcAleExplicitCredentialsQuery` returns `ERROR_ACCESS_DENIED` for admin; direct IOCTL `0x128010` skips the BFE RPC access check entirely, allowing credential extraction in admin context.

**Security descriptor bypass:** `WfpAllowBfeGenericAll` sets the device descriptor to block new handle creation (not duplication). Duplicating BFE's existing handle sidesteps the restriction without modifying the descriptor.

**Additional undocumented devices** for further research:
- `IPSECDOSP` — IOCTLs `0x124004`, `0x124002`
- `NXTIPSEC` — IOCTLs `0x128028`, `0x12801C`, `0x128018`
- `WFP` — IOCTLs `0x12803C`, `0x124050`, `0x128004`

## Detection and defence

**Detectable indicators:**
- New IPSec policies appearing outside known network topology — alert on `FwpmFilterAdd0` calls from non-sysadmin processes
- `DeviceIoControl` calls targeting `\Device\WfpAle` from processes other than `BFE` (svchost.exe hosting BFE service)
- Multiple sequential `WfpAleQueryTokenById` IOCTLs in rapid succession (LUID brute-force: 1–4096 iterations)
- `RpcOpenPrinter` calls with `\\127.0.0.1` as target while a custom IPSec policy is active
- `PROCESS_DUP_HANDLE` access to the BFE process (PID of the svchost hosting BFE)
- Handle duplication from BFE with WfpAle as the source handle

**WFP logging limitations:**
- Default WFP logs only dropped packets and IKE key-exchange failures
- Allowing packets requires explicit configuration (`FwpmNetEventSubscribe0`) — not recommended in production
- Even with full WFP logging enabled, logs show only generic filter names ("allows localhost communication") — no mention of the triggering RPC call or IPSec policy name

**Mitigations:**
- Restrict `SeDebugPrivilege` to absolute minimum accounts
- Monitor for unexpected IPSec policy creation events (Windows Event ID 4709, 4710)
- Endpoint detection via kernel ETW providers: `Microsoft-Windows-TCPIP` and `Microsoft-Windows-WFP`
- Audit `\Device\WfpAle` IOCTL activity via driver call stack inspection (Sysmon driver event, ETW)

## Tools

- **NoFilter** — PoC from Deep Instinct implementing all three attack chains; `https://github.com/deepinstinct/NoFilter`

## Sources

- Deep Instinct blog: "#NoFilter — Abusing Windows Filtering Platform for Privilege Escalation" (2023)
  `https://www.deepinstinct.com/blog/nofilter-abusing-windows-filtering-platform-for-privilege-escalation`
- Microsoft: no CVE issued; behaviour confirmed as by design
