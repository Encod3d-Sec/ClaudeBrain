---
title: "ICS / SCADA / OT Attacks (Modbus, S7, EtherNet/IP, OpenPLC)"
type: technique
tags: [ics, scada, ot, modbus, plc, s7comm, ethernet-ip, openplc, node-red, ctf, thm]
phase: exploitation
date_created: 2026-06-29
date_updated: 2026-06-29
sources: [thm-kaboom]
---

# ICS / SCADA / OT Attacks

Industrial Control Systems expose unauthenticated, unencrypted control protocols. The "vuln" is
usually that the protocol has NO auth: anyone who can reach the PLC can read sensors and write
setpoints/outputs. On CTF/OT boxes the goal is typically to drive the plant into a dangerous state
(over-pressure, over-speed, disable a safety interlock) and read the flag that the resulting HMI /
CCTV / alarm state reveals. See [[iot-attacks]], [[firmware-hardware]]. Payloads: [[modbus]].

## OT protocols + default ports

| Port | Proto | Notes / tool |
|------|-------|--------------|
| 502/tcp | **Modbus TCP** | coils/registers, no auth. `pymodbus`, `mbtget`, `modbus-cli`, nmap `modbus-discover`, msf `scanner/scada/modbusclient` |
| 102/tcp | **S7comm** (Siemens S7-300/400/1200) | data blocks. `python-snap7`, nmap `s7-info`, `plcscan`, msf `s7` modules |
| 44818/tcp (+2222/udp) | **EtherNet/IP / CIP** (Rockwell/Allen-Bradley) | tags. `pycomm3`, nmap `enip-info` |
| 20000/tcp | **DNP3** | nmap `dnp3-info` |
| 47808/udp | **BACnet** (building automation) | `BACnet-stack`, nmap `bacnet-info` |
| 1911,4911/tcp | **Niagara Fox** (Tridium) | nmap `fox-info` |
| 4840/tcp | **OPC-UA** | `opcua` python |
| 1880/tcp | **Node-RED** | flow-based SCADA glue; often a dashboard at `/ui` (unauth) + Modbus polling. See [[reverse-proxy-attacks]] is NOT it; admin API `/flows` is adminAuth |
| 80/8080/tcp | **HMI / OpenPLC web** | Flask/Werkzeug; OpenPLC default `openplc:openplc` |

## Recon
```bash
nmap -p- --min-rate 2500 -T4 -Pn $T                 # find the OT ports
nmap -Pn -p 102,502,20000,44818,47808 \
  --script s7-info,modbus-discover,enip-info,dnp3-info,bacnet-info $T
# modbus-discover finds the unit/slave id(s): "sid 0x1"
```
Identify the HMI (a web app on 80/8080 that reads the PLC) and Node-RED (1880). The HMI usually has
an `/api/...` that exposes the live plant state (it reads Modbus) - that is your oracle for whether
a write "worked".

## Modbus TCP (the workhorse)

Raw frame (no library needed - `pymodbus` is fragile across versions; a socket always works):
```
MBAP: transId(2) protoId(2=0) length(2) unitId(1)  +  PDU: funcCode(1) data...
FC1 read coils        FC2 read discrete inputs    FC3 read holding regs   FC4 read input regs
FC5 write 1 coil      FC6 write 1 holding reg     FC15 write N coils      FC16 write N holding regs
```
Reusable helper + the full read/write/sweep set live in [[modbus]].

**Enumerate everything, ASCII-decode registers** (creds/flags are sometimes stored as ASCII in
holding/input registers), then **sweep WIDE** - the interesting coil/register is rarely at address
0-5. On THM Kaboom the safety kill-switch was **coil 10**, invisible until sweeping 0-15.

## The OT-CTF pattern: drive the plant to a dangerous state

1. **Read the live state** via the HMI API (e.g. `/api/state` -> `{"status":..,"video":..}`) and the
   dashboard config to learn which register = which sensor (Node-RED `/ui` socket.io config names the
   widgets: "Read Pressure" = FC3 reg0, "Read Coils" = FC1).
2. **Over-drive the process variable**: `FC6` write the pressure/temp register to max (`65535`).
3. **Defeat the safety/protection interlock**: a controller loop (cooling, relief valve, ESD) will
   counteract you. It is usually a single **coil** you set/clear (`FC5`). Sweep coils 0-15(+) and
   watch the HMI state for the status flipping to the danger state.
4. **Read the payoff state**: the HMI flips to e.g. `"Explosion Detected!"` and points the CCTV at a
   new video/image. The **flag is frequently a visual overlay** in that media, NOT in
   strings/metadata -> fetch it, extract frames (`ffmpeg -i x.mp4 -vf fps=1 f_%02d.jpg`) and VIEW
   them.

## OpenPLC

OpenPLC Runtime = the soft-PLC behind the Modbus server on these boxes; its **Webserver** is the
Flask app on 8080 (routes `/programs /monitoring /hardware /settings /users`).
- Default creds `openplc:openplc` (often changed on CTF boxes -> then it is a rabbit hole; the
  protection can usually be disabled straight over Modbus instead of via the web "Stop PLC").
- Modbus address map: coils 0-799 = `%QX` outputs, discrete inputs = `%IX`, input regs = `%IW`,
  holding regs 0-1023 = `%QW`, 1024+ = `%MW`. Outputs you write via Modbus are overwritten by the
  running program each scan UNLESS the ladder reads that coil/reg as a flag/setpoint (the box's
  "disable protection" coil is exactly such a flag).
- Authenticated OpenPLC has a known **authenticated RCE** (upload a malicious ST/C program that gets
  compiled + run as the webserver user) - relevant once you have creds.

## S7comm (Siemens)
```python
import snap7
c=snap7.client.Client(); c.connect('IP',0,2)     # S7-300/400 rack 0 slot 2; S7-1200/1500 often 0,1
for db in range(1,30):
    try: print(db, bytes(c.db_read(db,0,128)))    # creds/flags hide in DBs
    except Exception: pass
```
Many CTF S7 services are **banner-only sims** (respond to `s7-info` SZL but expose no DBs and empty
CPU info) = decoy. Confirm with `db_read`/`get_cpu_info` before burning time.

## Detection / defence
- Segment OT from IT (the Purdue model); never expose 502/102/44818 to routable networks.
- Modbus/S7/DNP3 have optional or bolt-on auth at best - use a data diode / unidirectional gateway,
  and an OT-aware IDS (Zeek ICS, Snort ICS rules) watching for unexpected `FC5/FC6/FC15/FC16` writes.

## Tools
- `pymodbus` (+ `pymodbus.console`), `mbtget`, `modbus-cli`, raw socket (most reliable)
- `python-snap7` (S7), `pycomm3` (EtherNet/IP), `plcscan`, `opcua`
- Metasploit `auxiliary/scanner/scada/*` (modbusdetect, modbusclient, modbus_findunitid, ...)
- nmap ICS NSE: `modbus-discover s7-info enip-info dnp3-info bacnet-info fox-info`
- `conpot` (ICS honeypot, useful to learn the protocols offline)

## Sources
- THM "Kaboom" (Industrial Intrusion CTF) - Modbus over-pressure + coil-10 safety disable -> CCTV explosion video flag (`thm-kaboom`)
