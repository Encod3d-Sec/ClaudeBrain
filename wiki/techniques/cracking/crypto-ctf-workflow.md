---
title: "Crypto CTF Triage and Auto-Decode Workflow"
type: technique
tags: [crypto, ctf, encoding, compression, triage, cyberchef]
phase: exploitation
date_created: 2026-07-14
date_updated: 2026-07-14
sources: [hacktricks-crypto]
---

## What it is

The "what do I even have" triage that precedes any crypto attack: classify an unknown blob (encoding vs encryption vs hash vs signature vs MAC), peel layered encodings and hidden compression, and identify recurring named constructs before reaching for lattices or SMT. The companion to [[cryptography-attacks]], which covers the attacks themselves.

## How it works

Classify before attacking: is the blob an encoding, an encryption, a hash, a signature, or a MAC? Then note what you control (plaintext, ciphertext, IV/nonce, key, an oracle, or a partial leak) and pick the highest-probability check first. Escalate to lattices or SMT only when a cheap check fails.

## Attack phases
Exploitation (CTF challenge solving; applies to opaque tokens/blobs during web + app work).

## Prerequisites
- The blob and any surrounding context (headers, field names, how it is used server-side).
- Local crypto stack installed (see Tools).

## Methodology

### Fast identification and auto-decode
```bash
# many-base / many-layer auto decode
codext decode -i <string>          # python-codext, tries base families
# Ciphey / CyberChef "Magic" for layered encode+compress chains
```
Encoding tells: base64 uses `A-Za-z0-9+/=`; base32 uses `A-Z2-7=` (heavy `=` padding); Ascii85/base85 is dense punctuation, sometimes wrapped `<~ ~>`.

### Compression as an inner layer
Compression hides as an inner layer constantly. If output "almost" parses, check magic bytes: gzip `1f 8b`, zlib `78 01/9c/da`, zip `50 4b 03 04`, bzip2 `42 5a 68`, xz `fd 37 7a 58 5a 00`, zstd `28 b5 2f fd`. Raw DEFLATE (no header) is common; try both window settings:
```bash
python3 - <<'PY'
import sys, zlib
d = sys.stdin.buffer.read()
for w in (zlib.MAX_WBITS, -zlib.MAX_WBITS):   # -MAX = raw deflate
    try: print(zlib.decompress(d, wbits=w)[:200])
    except Exception: pass
PY
```

### Recurring named constructs
- Fernet: two base64 blobs (token + key), decode with `cryptography.fernet`.
- Shamir Secret Sharing: multiple shares + a threshold t.
- `openssl enc` output starting `Salted__` is passphrase-bruteforceable (`bruteforce-salted-openssl`).
- Swiss-army solvers: `RsaCtfTool`, `featherduster`, `cryptovenom`.

## Bypasses and variants
- Multi-layer chains: base -> XOR -> compress -> encrypt. Always re-`file`/entropy-check decoded output before assuming you are done.
- If a cheap check fails, escalate to modular-arithmetic / lattice / SMT work in SageMath or z3 (see [[cryptography-attacks]]).

## Tools
Local stack: `pip install pycryptodome gmpy2 sympy pwntools z3-solver` plus SageMath for modular arithmetic, CRT, and lattices. `codext`, Ciphey, CyberChef, `RsaCtfTool`, `featherduster`, `cryptovenom`, `bruteforce-salted-openssl`. Attacks: [[cryptography-attacks]]; encoding layers: [[encoding-transformations]].

## Sources

- HackTricks (crypto), ingest slug `hacktricks-crypto`.
