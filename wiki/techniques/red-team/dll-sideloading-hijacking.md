---
title: "DLL Sideloading and Hijacking"
type: technique
tags: [red-team, osep, evasion, persistence, initial-access, applocker-bypass, windows, lateral-movement]
phase: exploitation
date_created: 2026-06-18
date_updated: 2026-07-03
sources: [hijacklibs, microsoft-dll-search-order, osep-pen300]
---

# DLL Sideloading and Hijacking

## What it is

A class of techniques where a signed, trusted executable ends up loading an attacker-influenced DLL because of how Windows resolves DLL names (MITRE T1574). For authorized red-team / OSEP work it matters as a proxy-execution, AppLocker-bypass, persistence, and evasion primitive; for defenders it is a high-value audit and detection target. This page covers the concept, how to identify exposure, and how to detect/remediate it - not a weaponization recipe. Related: [[applocker-bypass]], [[endpoint-detection-and-response]], [[windows-persistence]].

## Why it happens: DLL search order

When a process loads a DLL by name (not a full path), the DLL is not a registered KnownDLL, and the import is not already resolved, Windows searches a defined order: the application directory first, then system directories, then directories in `%PATH%`. If an application directory or a `%PATH%` entry is writable by a lower-privileged user, the name can resolve to a file that user controls. Microsoft documents the full order under "Dynamic-Link Library Search Order".

Common categories of exposure:
- **Sideloading**: a signed application loads a companion DLL from its own (user-writable) directory.
- **Search-order hijacking**: a DLL appears earlier in the search path than the intended one.
- **Phantom hijacking**: an application attempts to load a DLL that does not exist on the system (an optional/missing dependency).

## Identifying exposure (audit / discovery)

This is the same workflow blue teams use to find and fix the issue:

```
# Procmon: filter Result = "NAME NOT FOUND" and Path ends with ".dll"
#   -> shows DLLs an app looks for but does not find (phantom/hijackable)
# Inspect what a binary imports / where from:
dumpbin /imports legit.exe        # or PE-bear / CFF Explorer
```

Reference catalogues of known-affected signed binaries: **hijacklibs.net** and the **LOLBAS** project. Discovery/auditing tools that automate this: `Spartacus`, `Robber`, `DLLSpy`.

## Why it is valuable (impact, conceptual)

- **AppLocker / WDAC bypass**: policies frequently allow the signed host EXE while DLL rules are not enforced by default, so loaded DLLs are not policy-checked. See [[applocker-bypass]].
- **Evasion**: code executing inside a trusted, module-backed image is harder for heuristics that flag unbacked private memory or anomalous call-stack origins ([[endpoint-detection-and-response]]).
- **Persistence**: an autostart/service/scheduled application that resolves a DLL from a writable location re-runs it on each launch ([[windows-persistence]]).
- **Privilege escalation**: a SYSTEM service that resolves a DLL from a user-writable path can lead to SYSTEM-level execution.
- **DLL proxying** is the idea of forwarding the genuine exports so the host application keeps functioning; relevant to understanding why this is stealthy and how to detect partial/forwarded export tables.

## Detection and defence

- **Sysmon Event ID 7 (ImageLoad)**: unsigned or unusual DLLs loaded by signed binaries from user-writable paths.
- **Procmon `NAME NOT FOUND`** for `.dll` on app launch reveals phantom loads to fix.
- Enforce **AppLocker DLL rules** (disabled by default) and **WDAC with ISG**; keep `SafeDllSearchMode` enabled.
- Ship applications that load dependencies by **full path** / with resolved delay-load forwarders, and that do not run from user-writable directories.
- Restrict write access to application and `%PATH%` directories; monitor those paths for new `.dll` files.

## Tools

`Procmon`, `dumpbin` / PE-bear / CFF Explorer (inspect imports/exports), discovery: `Spartacus`, `Robber`, `DLLSpy`, hijacklibs.net, LOLBAS.

## Sources

- HijackLibs project (slug: hijacklibs) (`https://hijacklibs.net/`).
- Microsoft - Dynamic-Link Library Search Order (slug: microsoft-dll-search-order).
- OffSec PEN-300 / OSEP syllabus (slug: osep-pen300).
