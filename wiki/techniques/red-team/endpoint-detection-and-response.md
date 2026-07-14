---
title: Endpoint Detection and Response
type: technique
tags: [edr, evasion, reference-import, windows, syscalls, unhooking, osep]
phase: post-exploitation
date_created: 2026-05-13
date_updated: 2026-07-02
sources: [InternalAllTheThings]
---

# Endpoint Detection and Response

## What it is

Endpoint Detection and Response (EDR) is a security solution that combines real-time monitoring, data collection, and advanced analytics to detect, investigate, and respond to cyber threats at the endpoint level. Leveraging machine learning algorithms and behavioral analysis, EDR tools can identify malicious activities, automate containment and remediation actions, and provide forensic insights to enhance an organization's overall security posture.

## How it works

EDR products monitor endpoint activity by hooking Win32 API calls in user-space, collecting kernel telemetry via ETW (Event Tracing for Windows), and applying behavioral detection rules to flag anomalous sequences of actions. Attackers bypass EDR using techniques such as direct syscalls (bypassing user-space hooks), API unhooking (restoring original ntdll.dll bytes), process injection into trusted processes, and AMSI bypass to prevent script scanning. Detection evasion is an arms race between EDR rule updates and attacker tooling that exploits gaps in instrumented API coverage.

## Attack phases

- **Exploitation**: primary phase for this note (credential and control-plane abuse)
- **Adjacent phases**: overlaps are common once credentials or lateral paths appear

## Prerequisites

Authorized scope covering the depicted systems; valid credentials or network reach as required by each command block inside the methodology body.

## Methodology

The following imported sections retain upstream ordering, tables, and copy-pasta blocks from InternalAllTheThings.

Endpoint Detection and Response (EDR) is a security solution that combines real-time monitoring, data collection, and advanced analytics to detect, investigate, and respond to cyber threats at the endpoint level. Leveraging machine learning algorithms and behavioral analysis, EDR tools can identify malicious activities, automate containment and remediation actions, and provide forensic insights to enhance an organization's overall security posture.

## Static Detection

**Mechanism**: Static detection is a security technique used in EDR and antivirus software that analyzes files and applications without executing them, typically based on predefined signatures or known malicious patterns.

**Bypass**:

- Obfuscate strings
- Dynamically resolving strings
- Dynamically resolving imports, reducing the `Import Address Table` (IAT)
- Custom `GetProcAddress` and `GetModuleHandle`
- API Hashing

## User Behavioural Analysis

**Mechanism**: User Behavioral Analysis (UBA) monitors and analyzes user activities and patterns to detect anomalies and potential threats.

**Bypass**:

- Learning about OPSEC methods

## Usermode Windows Function Monitoring

**Mechanism**: Usermode Windows Function Monitoring is a technique that tracks and analyzes the execution of Windows API (Application Programming Interface) calls and functions within user space processes. EDR installs **inline hooks** (a `jmp` to its own code) at the start of sensitive `ntdll.dll` Nt*/Zw* stubs to inspect arguments before the real syscall.

**Bypass**:

- **Unhooking**: restore the clean ntdll stub bytes. Map a **fresh copy of ntdll** from disk (`\KnownDlls\ntdll.dll`, a suspended-process copy, or the on-disk file) and overwrite the hooked `.text` of the loaded ntdll, removing the EDR jmp.
- **Direct syscalls**: skip ntdll entirely - place `mov r10,rcx; mov eax,<SSN>; syscall; ret` in your own code and invoke the kernel directly. The syscall number (SSN) varies by Windows build, so resolve it dynamically (**Hell's Gate**: read the SSN from the in-memory stub; **Halo's/Tartarus Gate**: walk neighbouring stubs when the target is hooked). Tooling: SysWhispers2/3, Syscalls.
- **Indirect syscalls**: same SSN resolution, but execute the `syscall` instruction **inside ntdll** (jump to a real `syscall;ret` gadget in ntdll) so the return address still points into ntdll - defeats call-stack origin checks that flag a `syscall` returning to non-module memory.

## Call Stack Analysis

**Mechanism**: Checking the origin of function calls via the Call Stack chain (a `syscall`/API call whose return address is unbacked private memory, or a thread start address outside a module, is suspicious).

**Bypass**:

- **Call-stack spoofing**: build a fake, legitimate-looking frame chain before the syscall (e.g. `Vulcan Raven`/`ThreadStackSpoofer`) so the return path looks like it came from a backed module.
- **Indirect syscalls** (above): the return address lands inside ntdll, so the stack origin looks normal.
- **Module-backed execution**: run the sensitive call from a thread whose start address is inside a real DLL (module stomping / DLL sideloading - see [[dll-sideloading-hijacking]]) instead of fresh `VirtualAlloc` RX memory.

## Process Analysis

**Mechanism**: Process analysis includes inspecting memory regions, identifying remote process access, and assessing child processes to gain insights into process relationships, uncover hidden or suspicious activities.

**Bypass**:

- Avoid RWX memory region (RW->RX)
- Break parent-child link (e.g: word.exe spawning cmd.exe)
- TODO

## Kernel Callbacks

**Mechanism**: Kernel callbacks in the context of Endpoint Detection and Response (EDR) are functions registered by kernel drivers that get triggered in response to specific events or actions within the operating system's kernel.

**Bypass**:

- TODO

## WDAC to Disable EDR Components

Place the WDAC policy `SiPolicy.p7b` inside `C:\Windows\System32\CodeIntegrity\` and reboot the machine.

```ps1
smbmap -u Administrator -p P@ssw0rd -H 192.168.4.4 --upload "/home/kali/SiPolicy.p7b" "ADMIN\$/System32/CodeIntegrity/SiPolicy.p7b"
smbmap -u Administrator -p P@ssw0rd -H 192.168.4.4 -x "shutdown /r /t 0"
```

Using Krueger a .NET post-exploitation tool.

- [logangoins/Krueger](https://github.com/logangoins/Krueger) - Proof of Concept (PoC) .NET tool for remotely killing EDR with WDAC

```ps1
inlineExecute-Assembly --dotnetassembly C:\Tools\Krueger.exe --assemblyargs --host ms01
```

## References

- [Flying Under the Radar: Part 1: Resolving Sensitive Windows Functions with x64 Assembly - theepicpowner - Apr 24, 2024](https://theepicpowner.gitlab.io/posts/Flying-Under-the-Radar-Part-1/)
- [Malware AV/VM evasion - part 16: WinAPI GetProcAddress implementation. Simple C++ example - cocomelonc](https://cocomelonc.github.io/malware/2023/04/16/malware-av-evasion-16.html)
- [Custom GetProcAddress And GetModuleHandle Implementation (X64) - daax - December 15, 2016](https://revers.engineering/custom-getprocaddress-and-getmodulehandle-implementation-x64/)
- [Weaponizing WDAC: Killing the Dreams of EDR - Jonathan Beierle and Logan Goins - December 20, 2024](https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/)

## Bypasses and variants

Enumerate case-specific bypasses inside the methodologies above when upstream documented alternate paths.

## Detection and defence

Apply vendor baselines for logging, least privilege, patch cadence, and segmentation. Map signals to SOC playbooks relevant to each platform referenced in this page.

## Tools

Tool references are inline in **Methodology**; see the `tools/` pages for CLI usage.

## Sources

- Swisskyrepo [InternalAllTheThings](https://github.com/swisskyrepo/InternalAllTheThings) (ingest slug `InternalAllTheThings`).
