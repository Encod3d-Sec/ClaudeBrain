---
name: hunt-ics
description: ICS/SCADA/OT exploitation - Modbus (502), S7comm (102), EtherNet/IP (44818), DNP3, OpenPLC, Node-RED SCADA, PLC/HMI/coil/holding-register attacks. Use when a target exposes industrial protocols or the goal is to drive a plant to a dangerous state (over-pressure/over-speed/disable interlock) and read the flag the HMI/CCTV reveals.
---

# Hunt: ICS / SCADA / OT

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "ICS SCADA modbus PLC" via wiki-search MCP -> read [[ics-scada-modbus]] + payloads [[modbus]].
```
**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/mobile-iot/ics-scada-modbus.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm in scope. OT writes can damage real equipment - on a real engagement, `no_dos`/`passive_only` means READ-ONLY (FC1-4), never write (FC5/6/15/16). On a CTF/lab, writing is the point.
- Read `Deadends.md`.

## Attack Surface Signals
Open OT ports: **502 (Modbus), 102 (S7/iso-tsap), 44818 (EtherNet/IP), 20000 (DNP3), 47808/udp (BACnet), 1911/4911 (Fox), 4840 (OPC-UA)**. Plus the IT side that drives them: an **HMI** (Flask/Werkzeug web app with an `/api/...` live-state endpoint), **OpenPLC** webserver (8080, routes `/programs /monitoring /hardware /users`), **Node-RED** (1880, dashboard `/ui`).

## Methodology
1. **Recon**: `nmap -p- ...` then `nmap -Pn -p102,502,20000,44818 --script s7-info,modbus-discover,enip-info,dnp3-info $T`. Note the unit/slave id ("sid 0x1").
2. **Find the oracle**: the HMI `/api/state`-style endpoint (it reads the PLC and tells you live status). Node-RED `/ui` socket.io config NAMES the registers ("Read Pressure" = FC3 reg0). This is how you know a write landed.
3. **Enumerate Modbus** (raw socket, not pymodbus): dump FC1-4, **ASCII-decode registers** (creds/flags hide there), scan unit ids. See [[modbus]].
4. **Map process variables -> registers/coils**. The pressure/temp/level sensor is a holding/input register; pumps/valves/cooling/safety are coils.
5. **Drive to the danger state (CTF goal)**: `FC6` over-drive the process variable to max (65535); then **defeat the safety/protection interlock** - a controller loop (cooling/relief/ESD) fights you, and it is usually ONE coil. **Sweep coils 0-15(+), watch the HMI oracle flip** to the danger state. The control coil is rarely at 0-5.
6. **Read the payoff**: HMI flips (e.g. "Explosion Detected!") and points the CCTV/HMI at new media. **The flag is frequently a VISUAL overlay** in that image/video - fetch it, `ffmpeg -i x.mp4 -vf fps=1 f_%02d.jpg`, and VIEW the frames (not strings/exif).
7. **S7**: `python-snap7` `db_read` the data blocks (creds/flags). Banner-only sims (s7-info works but no DBs) = decoy.
8. **OpenPLC**: try `openplc:openplc`; if changed, do NOT grind the login - the protection is usually disabled directly over Modbus (a coil flag the ladder reads). Authed OpenPLC = upload-program RCE.
9. **Distill to wiki (when confirmed):** if the finding is a reusable protocol-abuse technique or a new control-state mapping, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/mobile-iot/ics-scada-modbus.md`. Promote later via `scripts/wiki-promote.py`.

## Lessons (THM Kaboom)
- The challenge NARRATIVE is the literal solve ("over-pressure the pump -> blow-out", "disable the protection"). Map each phrase to a Modbus write before chasing web creds.
- Coils 0-5 were inert; the safety kill-switch was **coil 10** -> sweep WIDE.
- The OpenPLC login (`openplc:openplc` changed) was a rabbit hole that OOM'd the tooling host with a brute. Disable protection over Modbus instead.
- Flag was burned into the CCTV explosion video (`/video?mode=explodedflag23`), invisible to strings -> extract + view frames.

## FIND Output
```
Create Vulns/Research/FIND-XXX-SEVERITY-ics-<issue>-<host>.md
Severity: CRITICAL = unauthenticated write to a safety-critical coil/register (physical impact / ESD bypass); HIGH = unauth process-variable write; MEDIUM = unauth read of OT state.
Add row to Vuln-index.md
```
Exhausted (read-only, no writable control point, S7 banner-only, no oracle):
```
Append to Deadends.md: - [ ] ICS <host> -- <proto> read-only / sim-only; no writable control coil found (swept 0-31)
```

Report: Status + files created + flag/blocker.
