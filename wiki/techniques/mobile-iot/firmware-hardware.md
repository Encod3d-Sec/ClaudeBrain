---
title: "Firmware and Hardware Attacks"
type: technique
tags: [iot, firmware, hardware, uart, jtag, spi, binwalk, exploitation]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-07-14
sources: [hacktricks-hardware]
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

## Firmware anti-rollback / downgrade bypass and image acquisition

Signature checks without version/rollback checks let you flash an older, still-validly-signed image to reintroduce a patched bug. Workflow: obtain an old signed image (vendor CDN/support, third-party archives, or bundled inside the companion mobile app), serve it to any exposed update channel (web UI, app API, USB, TFTP, MQTT; many consumer devices accept unauthenticated base64 firmware blobs), then exploit the re-opened vuln, e.g. post-downgrade command injection:
```http
POST /check_image_and_trigger_recovery?md5=1;echo 'ssh-rsa AAAA...'>>/root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
```
Pull firmware straight out of an APK without touching hardware:
```bash
apktool d vendor-app.apk -o vendor-app
ls vendor-app/assets/firmware   # firmware_v1.3.11_signed.bin under assets/fw/ or res/raw/
```
A/B-slot validate-one/boot-another bypass: when the anti-rollback ratchet lives only in the updater (not the bootloader) and slot metadata is not cryptographically bound to the validated image digest, promote a current signed image to the passive slot, then (without rebooting) re-enter the slot-erase routine on that same promoted slot, write an older signed image, skip revalidation, and reboot; the bootloader checks only signature/CRC and boots the downgrade. When reversing, look for slot selection from stale boot-time flags, an erase routine keyed on stale state, and a layout-write that bumps a generation counter without storing the validated hash.

## IoT firmware loot and embedded exploitation (U-Boot env, derived tokens, fragmented-download overflow)

Concrete embedded techniques beyond the current binwalk/UART/flashrom basics:
- UART logs-only (RX ignored)? Force a root shell by editing the U-Boot env offline: dump SPI flash with a SOIC-8 clip (`flashrom -p ch341a_spi -r flash.bin`), locate the env partition, set `bootargs` to include `init=/bin/sh`, recompute the U-Boot env CRC32, reflash only the env partition, reboot.
- Derived-token cloud config / MQTT credential harvest: many hubs fetch config from `https://<host>/pf/<deviceId>/<token>` where `token = uppercase(MD5(deviceId || STATIC_KEY))`. Recover STATIC_KEY from the firmware (Ghidra/radare2, search `/pf/` or MD5 use), read deviceId from UART boot logs (`picocom -b 115200 /dev/ttyUSB0`), then:
```bash
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .   # often plaintext MQTT host/user/pass + topic prefix
```
Predictable OUI+type+sequential deviceIds enable authorized mass enumeration. Then subscribe to maintenance topics with `mosquitto_sub` if topic ACLs are weak.
- Fragmented-download heap overflow (recurring embedded bug class): the first fragment (`offset==0`) stores `total_size` and `malloc`s it; later fragments only validate packet-local fields and `memcpy(&buf[offset], chunk, chunk_len)` without re-checking the original allocation. Send a small declared total to force a small heap chunk, then a later fragment with the expected offset but a larger `chunk_len` to overflow. Drive the daemon into the model/blob-download FSM state first (device emulation, e.g. nRF52840 for Zigbee), and force the protocol's own error/retry path to trigger a predictable `free()` for allocator-metadata primitives (musl/uClibc/dlmalloc). Zigbee note: if the target still uses the default Link Key `ZigBeeAlliance09`, sniffed commissioning traffic can expose the Network Key.

## Sources

- HackTricks (hardware-physical-access), ingest slug `hacktricks-hardware`.
