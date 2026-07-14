---
title: "Physical Attacks"
type: technique
tags: [physical, red-team, bios, uefi, cold-boot, dma, bitlocker, hid, rowhammer]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-hardware]
---

## What it is

Attacks that need physical proximity or brief hands-on access to a machine: firmware/boot resets, memory-remanence and DMA reads, live-USB OS access, BitLocker key recovery, HID cable implants, sensor bypass, and hardware fault injection. With physical access, assume full compromise.

## How it works

Physical access defeats most software controls: firmware settings and NVRAM can be reset, DRAM retains data after power loss, boot media can be swapped, and peripheral buses (FireWire/Thunderbolt/USB) can write memory or inject input. Modern platform defenses (Secure Boot, DMA protection/VT-d, ECC, IOMMU) raise the bar but are partial, not complete.

## Attack phases
Exploitation (physical red-team, initial access via drop/implant, evil-maid).

## Prerequisites
- Physical access to the target for a bounded window; for some techniques a screwdriver, a Kali live USB, a logic analyzer, or a cable/board implant.

## Methodology

### Physical boot and media attacks (BIOS/UEFI, cold boot, DMA, live-USB, BitLocker)

- BIOS/UEFI reset: pull the CMOS battery ~30 min or short the reset jumper; software path off a Kali live USB with `killCmos`/`CmosPWD`; three wrong BIOS passwords yields an error code usable at bios-pw.org. Disable Secure Boot / inspect UEFI with chipsec: `python chipsec_main.py -module exploits.secure.boot.pk`.
- Cold-boot: RAM holds data 1-2 min after power loss (extendable by chilling the chips); dump and analyze with `dd` + Volatility before it fades.
- DMA: INCEPTION over FireWire/Thunderbolt patches memory to accept any login password (not effective on modern Win10+ with DMA protection/VT-d).
- Live-USB OS access: replace `sethc.exe`/`Utilman.exe` with `cmd.exe` for a SYSTEM prompt at the lock screen; edit the SAM with `chntpw`; Kon-Boot bypasses Windows/Linux login by patching the kernel/UEFI in memory.
- BitLocker: recover the key from a memory dump (`MEMORY.DMP`) with Elcomsoft/Passware; or social-engineer a user into adding an all-zero recovery key. `Shift` after the Windows banner can bypass autologon.

### Modern physical red-team and hardware attacks (chassis reset, Wi-Fi HID implants, IR sensor bypass, GPU Rowhammer)

Recent techniques that need nothing but proximity or a screwdriver:
- Chassis-intrusion / maintenance-switch factory reset: the switch is wired to an EC GPIO; some vendors ship an undocumented press-pattern that wipes NVRAM/CMOS, clearing supervisor password and Secure Boot keys, then boot any external OS. Framework 13 example: hold the intrusion switch 2 s, release, wait 2 s, repeat 10x while powered, reboot. ~40 s. Mitigate with tamper-evident seals and disabling the maintenance-reset feature.
- Wi-Fi HID cable implants (Evil Crow Cable Wind, ESP32-S3 hidden in a USB cable): enumerates as a keyboard, exposes C2 over its own Wi-Fi AP (`http://cable-wind.local/`). OS-aware AutoExec fires a payload right after enumeration (`GUI r` -> hidden PowerShell download-cradle on Windows; Spotlight/terminal curl on macOS/Linux). A HID-typed serial loop bridged to the ESP32 TCP client yields a blind remote shell even on air-gapped hosts. Unauthenticated OTA at `/update` lets you hot-swap firmware: `curl -F "file=@fw.bin" http://cable-wind.local/update`. BadUSB predecessors: Rubber Ducky, Teensyduino.
- Covert IR injection against no-touch "wave-to-exit" sensors: the receiver only counts pulses of the ~30 kHz carrier and assumes any validated burst is a nearby reflection. Capture the post-detection waveform with a logic analyzer, replay it with an external IR LED in tuned bursts (short on/off to avoid AGC desensitization), and bounce a high-power IR beam off interior surfaces through glass to trigger the door relay from ~6 m. Weaponizable inside a flashlight (IR LED + ATtiny + MOSFET + zoom lens).
- GPU Rowhammer on page tables (GDDRHammer/GeForge/GPUBreach, GDDR6 Ampere): unprivileged CUDA hammers rows, massages driver allocations so page-table/page-directory structures land in vulnerable rows, then flips a PFN/aperture bit to bootstrap arbitrary GPU read/write and (IOMMU disabled) arbitrary host memory. GPUBreach pivots to a root shell even with IOMMU on via a driver memory-safety bug. ECC and IOMMU are partial, not complete, mitigations.

## Bypasses and variants
- Kiosk/thin-client physical access: also try the GUI-application escapes in [[kiosk-escape-and-jail-breakout]].
- Embedded/IoT hardware (UART/JTAG/SPI flash dump, U-Boot env): see [[firmware-hardware]].

## Detection and defence
Tamper-evident seals + chassis-intrusion logging, disable maintenance-reset, BIOS/UEFI passwords + Secure Boot with custom keys, DMA protection/VT-d/IOMMU on, full-disk encryption with TPM+PIN (pre-boot auth), disable boot from external media, USB port control/allowlisting for HID, ECC memory. None is sufficient alone against a determined physical attacker.

## Tools
Kali live USB, `chntpw`, Kon-Boot, chipsec, Volatility, Elcomsoft/Passware, `CmosPWD`/`killCmos`, logic analyzer, Evil Crow Cable / Rubber Ducky (HID), CUDA (Rowhammer PoCs). Related: [[kiosk-escape-and-jail-breakout]], [[firmware-hardware]], [[initial-access]].

## Sources

- HackTricks (hardware-physical-access), ingest slug `hacktricks-hardware`.
