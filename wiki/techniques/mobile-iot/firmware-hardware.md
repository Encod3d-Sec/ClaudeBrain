---
title: "Firmware and Hardware Attacks"
type: technique
tags: [iot, firmware, hardware, uart, jtag, spi, binwalk, exploitation]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## What it is

Extracting and analysing embedded-device firmware, and accessing hardware debug/storage interfaces (UART, JTAG/SWD, SPI flash) to obtain a shell, dump secrets, or find vulnerabilities. Extends [[iot-attacks]] beyond the network/MQTT layer.

## How it works

IoT/embedded devices store firmware in flash (often unencrypted) and expose debug interfaces on the PCB. Firmware unpacks to a filesystem holding binaries, configs, keys, and creds; hardware interfaces give bootloader/console access or a direct memory/flash read.

## Attack phases
Exploitation (device assessment; supply-chain / embedded research).

## Prerequisites
- A firmware image (vendor download, OTA capture, or flash dump). For hardware: the physical device, USB-UART/JTAG adapter, multimeter, optionally a SOIC clip + flash programmer.

## Methodology

### 1. Obtain firmware
- Vendor support/download portal; intercept the OTA update URL; or dump from flash (hardware path below).

### 2. Unpack + analyse (software)
```bash
binwalk firmware.bin              # identify; [[binwalk]]
binwalk -Me firmware.bin          # recursive extract -> squashfs-root/
# loot the rootfs:
grep -rIn "password\|admin\|BEGIN .*PRIVATE KEY\|api[_-]key" squashfs-root/
cat squashfs-root/etc/shadow      # crack -> [[hashcat]] / [[password-cracking]]
ls squashfs-root/etc/init.d squashfs-root/www   # services + web UI source
```
`binwalk -E` for entropy (flat high = encrypted firmware -> need hardware dump or key). Find the bootloader env, hardcoded creds, backdoor accounts, vulnerable services.

### 3. Emulate
```bash
# user-mode emulation of a single binary
qemu-arm-static -L squashfs-root squashfs-root/usr/bin/<svc>
# full-system: firmadyne / FirmAE
./run.sh <brand> firmware.bin     # boots the image, exposes the web UI for testing
```
Then test the web/network surface as normal ([[os-command-injection]] is extremely common in IoT web UIs).

### 4. Hardware interfaces
- **UART** (3 pads: TX/RX/GND): identify with multimeter/logic analyzer; `screen /dev/ttyUSB0 115200` -> boot log + console/U-Boot. Interrupt boot for a root shell or `setenv bootargs init=/bin/sh`.
- **SPI flash** (SOIC-8): clip + `flashrom -p <programmer> -r dump.bin` to read the chip directly (bypasses firmware encryption-at-rest if the chip is plaintext).
- **JTAG/SWD**: `openocd` -> halt CPU, read memory/flash, set breakpoints (`telnet localhost 4444`).

## Bypasses and variants
- Encrypted firmware: pull plaintext from SPI flash, or find the decryption key in the bootloader/an earlier unencrypted version.
- Secure boot present: look for a debug/UART bypass or downgrade to vulnerable firmware.

## Detection and defence
Signed + encrypted firmware, disabled/locked JTAG and serial console in production, secure boot, no hardcoded creds/keys, eFuse-protected keys.

## Tools
[[binwalk]], `firmadyne`/FirmAE, `qemu-*-static`, `flashrom`, `openocd`, USB-UART adapter, logic analyzer. Web layer -> [[os-command-injection]]; creds -> [[hashcat]].

## Sources
