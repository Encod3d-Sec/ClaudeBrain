---
title: "Steganography"
type: technique
tags: [steganography, ctf, forensics, lsb, image, audio]
phase: post-exploitation
date_created: 2026-06-16
date_updated: 2026-06-16
sources: []
---

## What it is

Data hidden inside carrier media (images, audio, files, text) so its presence is concealed. Almost exclusively a CTF category, but the techniques overlap with covert-channel exfiltration.

## How it works

Carriers have redundant capacity: low-order bits of pixels/samples, metadata fields, space after logical EOF, or imperceptible character variants. Stego embeds payload there; extraction reverses the embedding or brute-forces a passphrase.

## Attack phases
Post-exploitation / analysis (CTF; covert exfil awareness).

## Prerequisites
- The carrier file. A passphrase or wordlist for tools like steghide.

## Methodology

### Always first
```bash
file f;  exiftool f;  strings -n6 f;  binwalk f      # metadata, appended/embedded data
binwalk -e f                                         # extract zip/file hidden after EOF
```

### Images
```bash
zsteg -a image.png                  # PNG/BMP LSB, all channels/bit-orders
steghide extract -sf image.jpg      # JPG/BMP/WAV, passphrase-protected
stegseek image.jpg rockyou.txt      # brute steghide passphrase (fast)
outguess -r image.jpg out.txt
pngcheck -v image.png               # malformed chunks / appended data
```
- **stegsolve** (or `convert`): cycle bit planes and colour channels; look for QR/text in a single plane. LSB-extract scripts for custom embeddings.
- Compare to original if provided: `cmp` / visual diff reveals modified pixels.

### Audio
- Spectrogram view (Audacity / sonic-visualiser) -> text/SSTV image hidden in frequencies.
- LSB in WAV (`WavSteg`, `stego-lsb`). DTMF tones (`multimon-ng`), Morse, reversed/slowed audio.

### Files / containers
- Polyglots (file valid as two types); ZIP appended to image (`binwalk`/`unzip`); password ZIP -> `zip2john` + [[hashcat]].
- NTFS Alternate Data Streams (`dir /R`, `streams.exe`); PDF/Office embedded objects.

### Text
- Zero-width characters / unicode steg (whitespace tools, `stegsnow`); base/rot layers -> [[encoding-transformations]]; whitespace `snow`.

## Bypasses and variants
- Multi-stage: image -> embedded zip (password in EXIF) -> stego inside extracted file. Re-run the full triage on every extracted artifact.
- Unknown tool: entropy + known headers narrow the embedding scheme.

## Detection and defence
Strip metadata on upload, re-encode media (destroys LSB payloads), entropy/steganalysis scanning.

## Tools
`steghide`, `stegseek`, `zsteg`, `binwalk` ([[binwalk]]), `exiftool`, stegsolve, sonic-visualiser / Audacity, `stegsnow`, `outguess`. Pairs with [[digital-forensics]].

## Sources
