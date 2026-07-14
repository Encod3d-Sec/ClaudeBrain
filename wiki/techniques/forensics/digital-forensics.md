---
title: "Digital Forensics"
type: technique
tags: [forensics, ctf, memory, disk, pcap, volatility, incident-response]
phase: post-exploitation
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## What it is

Recovering evidence and hidden data from disk images, memory dumps, packet captures, and file artifacts. A CTF category and the core skill of incident response / DFIR.

## How it works

Data persists in structure (filesystem metadata, process memory, packet streams) and in slack/deleted regions. Forensics parses these structures and carves data that was deleted, embedded, or in transit.

## Attack phases
Post-exploitation / analysis (CTF forensics; IR; evidence extraction).

## Prerequisites
- The artifact (image/dump/pcap) and its type. For memory: the OS profile/symbols.

## Methodology

### File triage (start here)
```bash
file artifact;  binwalk artifact            # embedded files/signatures ([[binwalk]])
binwalk -e artifact                         # extract; foremost/scalpel for carving
exiftool artifact;  strings -n8 artifact;  xxd artifact | head
```
Wrong/mismatched magic bytes -> fix header. Appended data after EOF -> carve. See [[steganography]] for media-embedded data.

### Memory forensics (Volatility 3)
```bash
vol -f mem.raw windows.info                 # identify build
vol -f mem.raw windows.pslist;  windows.pstree;  windows.cmdline
vol -f mem.raw windows.netscan              # connections
vol -f mem.raw windows.filescan | grep -i flag
vol -f mem.raw windows.dumpfiles --virtaddr 0x...
vol -f mem.raw windows.hashdump;  windows.lsadump;  windows.cachedump
vol -f mem.raw windows.malfind              # injected code
# Linux: linux.pslist / linux.bash (shell history)
```
`bulk_extractor mem.raw -o out` pulls emails, URLs, card numbers, keys.

### Disk forensics
```bash
mmls disk.img;  fls -r -o <offset> disk.img    # sleuthkit: partition + file listing
icat -o <offset> disk.img <inode> > recovered  # extract by inode (incl. deleted)
```
Autopsy GUI for timeline + deleted files. Windows: parse `$MFT`, registry (`regripper`), `NTUSER.dat`, prefetch, `$Recycle.Bin`, browser DBs, event logs (`evtx_dump`).

### Network forensics (pcap)
```bash
tshark -r cap.pcap -q -z io,phs             # protocol hierarchy ([[tshark]])
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri
tcpflow -r cap.pcap;  foremost -i cap.pcap   # reassemble streams / carve files
```
- Wireshark: Follow TCP/HTTP Stream; File > Export Objects (HTTP/SMB/FTP). Credentials in cleartext protocols.
- TLS decrypt: load `SSLKEYLOGFILE`. USB pcap: decode HID keystrokes from `usb.capdata`. ICMP/DNS exfil: reassemble payload bytes.

### Logs / timeline
`log2timeline.py` + `psort.py` (plaso) for super-timelines; grep auth/access logs for the intrusion path.

## Bypasses and variants
- Corrupted headers: repair PNG/ZIP/PDF magic + CRC (`pngcheck`, `zip -FF`).
- Encrypted volumes: VeraCrypt/BitLocker key in memory dump (`vol ... bitlocker`); ZIP/Office hash -> [[hashcat]].

## Detection and defence
Full-disk encryption, log integrity (append-only/remote), memory-acquisition resistance, secure deletion.

## Tools
`volatility3`, [[binwalk]], Wireshark / [[tshark]], `foremost`, `exiftool`, Autopsy / sleuthkit, `bulk_extractor`, `regripper`, plaso. See [[steganography]], [[encoding-transformations]].

## Sources
