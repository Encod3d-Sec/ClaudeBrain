---
title: "Nmap Cheatsheet"
type: cheatsheet
tags: [cheatsheet, enumeration, htb, network, nmap, recon, scanner]
date_created: 2026-05-08
date_updated: 2026-05-08
sources: [cpts-nmap]
---

## Host Discovery

```bash
sudo nmap 10.129.2.0/24 -sn -oA sweep           # Ping sweep a subnet (no port scan)
sudo nmap -sn -oA sweep -iL hosts.txt            # Ping sweep from host list
sudo nmap -sn -PE target                         # ICMP echo request discovery
sudo nmap -sn -PP target                         # ICMP timestamp discovery
sudo nmap -sn -PM target                         # ICMP address mask discovery
sudo nmap -sn -PS80,443 target                   # TCP SYN ping (custom port)
sudo nmap -Pn target                             # Skip discovery — treat host as alive
```

## Port Scanning

```bash
sudo nmap -sS target                             # TCP SYN scan (stealth, requires root)
nmap -sT target                                  # TCP connect scan (no root needed)
sudo nmap -sU target                             # UDP scan (slow)
sudo nmap -sSU target                            # Combined TCP SYN + UDP
sudo nmap -p 22,80,443 target                    # Specific ports
sudo nmap -p 1-1000 target                       # Port range
sudo nmap -p- target                             # All 65535 ports
sudo nmap --top-ports 100 target                 # Top 100 common ports
sudo nmap --top-ports 1000 target                # Top 1000 (default)
sudo nmap -p- --min-rate 5000 target             # Fast full-port scan
```

## Service and Version Detection

```bash
nmap -sV target                                  # Service/version detection
nmap -sV --version-intensity 0 target            # Fast, low-accuracy version probe
nmap -sV --version-intensity 9 target            # Maximum version detection effort
nmap -O target                                   # OS detection (requires root)
nmap -A target                                   # Aggressive: -sV -sC -O --traceroute
```

## Default Scripts

```bash
nmap -sC target                                  # Run default NSE scripts
nmap -sV -sC target                              # Version + default scripts
nmap -A target                                   # All: version + scripts + OS + traceroute
```

## NSE Scripts

```bash
nmap --script=http-enum target                   # Run specific script
nmap --script=vuln target                        # All scripts in vuln category
nmap --script="http-*" target                    # Wildcard: all http-* scripts
nmap --script=default,safe target                # Multiple categories
nmap --script=auth target                        # Auth bypass/credential tests
nmap --script=brute target                       # Brute-force credential scripts
nmap --script=discovery target                   # Asset discovery scripts
nmap --script=exploit target                     # Active exploitation (use with care)
nmap --script-args user=admin,pass=admin target  # Pass arguments to scripts
nmap --script-help http-enum                    # Script documentation
```

Script categories: `auth`, `brute`, `default`, `discovery`, `exploit`, `fuzzer`, `intrusive`, `safe`, `vuln`

Scripts location: `/usr/share/nmap/scripts/`

## Output Formats

```bash
nmap target -oN output.txt                       # Normal (human-readable)
nmap target -oX output.xml                       # XML (for import into tools)
nmap target -oG output.gnmap                     # Grepable
nmap target -oA output                           # All three formats simultaneously
nmap target -oA scan && grep "open" scan.gnmap   # Quick grep for open ports
```

## Timing Templates

```bash
nmap -T0 target    # Paranoid  — very slow, IDS evasion
nmap -T1 target    # Sneaky    — slow, IDS evasion
nmap -T2 target    # Polite    — slow, reduces bandwidth usage
nmap -T3 target    # Normal    — default
nmap -T4 target    # Aggressive — faster, assumes reliable network
nmap -T5 target    # Insane    — very fast, may miss open ports
```

## Firewall / IDS Evasion

```bash
sudo nmap -f target                              # Fragment packets (8-byte chunks)
sudo nmap -ff target                             # Fragment into 16-byte chunks
sudo nmap -D RND:10 target                       # Spoof 10 random decoy IPs
sudo nmap -D 10.0.0.1,10.0.0.2,ME target        # Specific decoy IPs
sudo nmap --data-length 50 target                # Pad packets with 50 random bytes
sudo nmap --source-port 53 target                # Spoof source port as 53 (DNS)
sudo nmap --scan-delay 500ms target              # Delay between probes
sudo nmap --max-retries 1 target                 # Reduce retransmissions
sudo nmap -sS -T1 -f -D RND:5 target            # Combined stealth approach
```

## Combining Flags (Practical Examples)

```bash
# Quick version scan of common ports
sudo nmap -sS -sV --top-ports 1000 -oA quick_scan target

# Full port + service + default scripts (standard engagement)
sudo nmap -p- -sV -sC --min-rate 5000 -oA full_scan target

# UDP top ports
sudo nmap -sU --top-ports 200 -oA udp_scan target

# Stealthy scan with decoys and fragmentation
sudo nmap -sS -T2 -f -D RND:5 --source-port 53 -oA stealth target

# Network sweep then scan live hosts
sudo nmap -sn -oA sweep 10.10.10.0/24
cat sweep.gnmap | grep "Up" | awk '{print $2}' > live_hosts.txt
sudo nmap -iL live_hosts.txt -sV -sC -oA live_scan

# All ports with fast rate, then version scan only open ports
sudo nmap -p- --min-rate 5000 -oA allports target
# Extract open ports and rescan:
ports=$(grep "open" allports.gnmap | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')
sudo nmap -p "$ports" -sV -sC -oA targeted target
```

## Useful Flags Reference

```bash
-iL hosts.txt          # Input from file
-v / -vv               # Increase verbosity
--open                 # Only show open ports
--reason               # Show reason for port state
--packet-trace         # Show all sent/received packets
--disable-arp-ping     # Disable ARP-based host discovery
--max-hostgroup N      # Max hosts scanned in parallel
--min-rate N           # Minimum packets per second
--max-rate N           # Maximum packets per second
-n                     # No DNS resolution (faster)
-R                     # Always resolve DNS
```
