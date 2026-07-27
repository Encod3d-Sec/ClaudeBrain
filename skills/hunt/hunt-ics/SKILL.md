---
name: hunt-ics
description: ICS/SCADA/OT exploitation - Modbus (502), S7comm (102), EtherNet/IP (44818), DNP3, OpenPLC, Node-RED SCADA, PLC/HMI/coil/holding-register attacks. Use when a target exposes industrial protocols or the goal is to drive a plant to a dangerous state (over-pressure/over-speed/disable interlock) and read the flag the HMI/CCTV reveals.
---

# Hunt: ICS / SCADA / OT

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## SAFETY - hard stop, overrides everything below

Writing to a live PLC moves real machinery: it can over-pressure a vessel, over-speed a motor, or disable a safety interlock, and so **damage equipment or injure and kill people**. Only ever drive a process toward a dangerous state on a target that is EXPLICITLY an authorized lab or CTF simulation. Never on a real plant, and never when scope carries `no_dos`/`passive_only` - there OT is READ-ONLY (FC1-4), never write (FC5/6/15/16). The instant the objective is met (e.g. the flag the HMI/CCTV reveals is in hand), STOP writing and revert any coil/register you changed if you can. This is a hard stop and it outranks every other note in this file.

## Wiki

```
qmd_query "ICS SCADA OT Modbus S7comm EtherNet/IP DNP3 OpenPLC Node-RED PLC HMI coil holding register" via wiki-search MCP
```

Hub: [[network-moc]] (live index). Primary page: [[ics-scada-modbus]]. Payload arsenal: `wiki/payloads/modbus.md`.
Anchors: [[iot-attacks]], [[firmware-hardware]].

## Attack surface (ranked by exploitation value)

1. **Modbus / TCP 502** - no auth, no session, trivially readable AND writable. The primary lever: FC1-4 read coils/registers, FC5/6/15/16 write them. Highest value, highest danger.
2. **OpenPLC web (8080)** and **Node-RED (1880, dashboard `/ui`)** - the SCADA/IT side that drives the PLC. OpenPLC routes `/programs /monitoring /hardware /users`; authed OpenPLC = upload-program RCE. Node-RED `/ui` socket.io config NAMES the registers.
3. **HMI web app** (Flask/Werkzeug with an `/api/...` live-state endpoint) - not itself the lever but the ORACLE that tells you whether a write landed.
4. **S7comm / TCP 102** (S7/iso-tsap) - `python-snap7` `db_read` for creds/flags in data blocks.
5. **EtherNet/IP 44818**, **DNP3 20000**, then **BACnet 47808/udp**, **Fox 1911/4911**, **OPC-UA 4840** - enumerate with the matching nmap scripts; less commonly the CTF lever, but map them.

## Methodology
1. **Recon**: `nmap -p- ...` then `nmap -Pn -p102,502,20000,44818 --script s7-info,modbus-discover,enip-info,dnp3-info $T`. Note the unit/slave id ("sid 0x1").
2. **Find the oracle**: the HMI `/api/state`-style endpoint (it reads the PLC and tells you live status). Node-RED `/ui` socket.io config NAMES the registers ("Read Pressure" = FC3 reg0). This is how you know a write landed.
3. **Enumerate Modbus** (raw socket, not pymodbus): dump FC1-4, **ASCII-decode registers** (creds/flags hide there), scan unit ids. Reads (FC1-4) are safe; this step never writes. See [[modbus]].
4. **Map process variables -> registers/coils**. The pressure/temp/level sensor is a holding/input register; pumps/valves/cooling/safety are coils.
5. **Drive to the danger state (authorized lab/CTF ONLY - see SAFETY)**: `FC6` over-drive the process variable to max (65535); then **defeat the safety/protection interlock** - a controller loop (cooling/relief/ESD) fights you, and it is usually ONE coil. Find it with a BOUNDED, one-write-at-a-time probe, NEVER a free-running write loop (hunt-core: never enumerate writes; this narrow, reverting, oracle-gated probe on an authorized simulation is the sole carve-out): write ONE coil (FC5), read the HMI oracle, and if the state did not flip toward the goal, write that coil back before trying the next. Cover coils 0-31 this way - the control coil is rarely at 0-5, so go wide but stay bounded. If nothing in 0-31 flips the interlock, that is a Deadend; do not widen indefinitely.
6. **Read the payoff**: HMI flips (e.g. "Explosion Detected!") and points the CCTV/HMI at new media. **The flag is frequently a VISUAL overlay** in that image/video - fetch it, `ffmpeg -i x.mp4 -vf fps=1 f_%02d.jpg`, and VIEW the frames (not strings/exif). Objective met -> stop writing (SAFETY).
7. **S7**: `python-snap7` `db_read` the data blocks (creds/flags). Banner-only sims (s7-info works but no DBs) = decoy.
8. **OpenPLC**: try `openplc:openplc`; if changed, do NOT grind the login - the protection is usually disabled directly over Modbus (a coil flag the ladder reads). Authed OpenPLC = upload-program RCE.
9. **Distill (when confirmed):** stage a GENERIC candidate - `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/mobile-iot/ics-scada-modbus.md`.

## Chaining
- HMI / Node-RED web app -> read the `/api/state` oracle and the register NAMES -> know exactly which Modbus address is the process variable and which is the interlock, instead of guessing blind.
- OpenPLC authed (default `openplc:openplc`) -> upload-program RCE on the SCADA host -> shell, not just process control. Prefer disabling protection over unauthenticated Modbus first (cheaper, no login grind).
- Danger state reached -> the payoff media (CCTV/HMI overlay) -> flag. The Modbus write is the pivot; the flag is in the frame (step 6).

## Evasion
- Wrong **unit/slave id** looks like a dead PLC: if FC1-4 error out, scan unit ids (the `modbus-discover` "sid" value) before concluding the device is read-only or absent.

## Lessons (THM Kaboom)
- The challenge NARRATIVE is the literal solve ("over-pressure the pump -> blow-out", "disable the protection"). Map each phrase to a Modbus write before chasing web creds.
- Coils 0-5 were inert; the safety kill-switch was **coil 10** -> sweep WIDE (still bounded and reverting, per step 5).
- The OpenPLC login (`openplc:openplc` changed) was a rabbit hole that OOM'd the tooling host with a brute. Disable protection over Modbus instead.
- Flag was burned into the CCTV explosion video (`/video?mode=explodedflag23`), invisible to strings -> extract + view frames.

## Confirmation gate

**NOT confirmation:** a Modbus/S7/EtherNet-IP port open and banner-grabbed; a coil/register/data-block you can only READ; an FC1-4 dump that returns values; the HMI showing a value you did not change; a write (FC5/6/15/16) that returned an ACK with no observed state change. A readable register alone proves reachability, not control.

**IS confirmation (control/impact finding):** a coil/register you WROTE whose effect is observed on the oracle - the HMI / Node-RED live-state flips to the intended (danger) state, the simulated process variable moves, or the interlock is demonstrably defeated - reproduced on a clean connection, culminating in the payoff (the flag the HMI/CCTV reveals). No observed effect = no control finding; log it as reachability at most.

An unauthenticated READ of OT state is a valid lower-severity finding in its own right (confirmed by demonstrating the unauth read), but it is NOT a control or physical-impact claim - keep the two separate.

## Severity

| Demonstrated impact | Rating |
|---|---|
| Unauth write to a safety-critical coil/register - physical impact, ESD or interlock bypass | critical |
| Unauth process-variable write (no safety bypass) | high |
| Unauth read of OT state (registers/coils/data blocks) | medium |

## Deadends

```
Append: - [ ] ICS <host> -- <proto> read-only / sim-only; no writable control coil found (swept 0-31)
```

Record the range you swept and whether an oracle existed, so the next pass does not re-run the same bounded probe.
