---
title: "Cryptography Attacks (CTF + Applied)"
type: technique
tags: [crypto, ctf, rsa, aes, padding-oracle, ecdsa, prng, hash-length-extension]
phase: exploitation
date_created: 2026-06-16
date_updated: 2026-07-05
sources: []
---

## What it is

Breaking cryptography through implementation flaws and misuse rather than brute force: weak parameters, mode misuse, oracle leaks, nonce/key reuse, and predictable randomness. The dominant CTF crypto category and a real-world finding class (JWT, TLS, custom token schemes).

## How it works

Textbook primitives are secure; deployments are not. Attacks exploit small exponents, repeated nonces, malleable modes, side-channel oracles, and homebrew constructions. Identify the primitive, find the misuse, apply the matching attack.

## Attack phases
Exploitation (CTF challenge solving; applied to JWT/token/TLS findings during web + AD work).

## Prerequisites
- The ciphertext/scheme, and ideally the source or an oracle (encrypt/decrypt endpoint, error differences, timing).
- Public parameters (RSA `n,e`; curve; IV/nonce handling).

## Methodology

### RSA
```bash
# triage: factor n, weak params, then decrypt
RsaCtfTool --publickey key.pem --uncipher cipher.bin   # tries 30+ attacks
python3 -c "import factordb"   # factordb.com lookup for known n
```
- Small `e` (e=3) + short message -> cube root (`gmpy2.iroot(c,3)`); Hastad broadcast (same m, e recipients).
- Close primes -> Fermat factorization. Small `d` -> Wiener. Shared prime across keys -> batch GCD.
- Common modulus (same n, two e, gcd(e1,e2)=1) -> extended Euclid. LSB/parity decryption oracle -> binary search plaintext.

### Block ciphers (AES/DES)
- **ECB**: identical plaintext blocks -> identical ciphertext. Cut-and-paste blocks; byte-at-a-time ECB decryption against an encryption oracle (append controlled prefix).
- **CBC bit-flipping**: XOR ciphertext block `C[i-1]` to flip chosen plaintext bytes in `P[i]` (e.g. flip `admin=0` -> `admin=1`).
- **CBC padding oracle**: decryption error vs padding error distinction -> `padbuster URL ciphertext blocksize`; recover/forge plaintext without the key. **Forging (CBC-R) is the payload**, not just decryption: if the decrypted value is *used* server-side (run as a shell command, put in a SQL query, deserialized), forge a ciphertext decrypting to your injection -> **RCE/SQLi without the key** (THM Decryptify: decrypted `?date=` was run via `shell_exec`, output echoed; forge `cat /flag` -> RCE). Fingerprint the cipher from the openssl error it leaks: an **8-byte IV/block = a 64-bit cipher (DES/3DES/Blowfish/CAST5), NOT AES** (16-byte) -- stop trying AES keys. Oracle signal = a distinct "padding error" string vs a clean render. No `padbuster`? A ~60-line Python oracle does decrypt + CBC-R encrypt (recover intermediate `D(C)` byte-by-byte, then `IV/prev = D(C) xor P`).
- **Keystream/OTP reuse** (CTR, stream, reused IV): `C1 xor C2 = P1 xor P2` -> crib-drag. GCM nonce reuse -> forge auth tag (recover H).

### Hashes
- **Length extension** (MD5/SHA1/SHA256 MAC = `H(secret||msg)`): `hashpump -s sig -d known -a append -k keylen` to forge valid MAC for extended message.
- Weak hash collisions (MD5 chosen-prefix). Cracking -> see [[hash-capture-and-cracking]] and [[password-cracking]].

### PRNG / randomness
- Mersenne Twister: 624 consecutive 32-bit outputs -> recover state -> predict (`randcrack`). LCG: solve from a few outputs. Time-seeded -> brute the seed window. See [[insecure-randomness]].
- **Seed-from-known-inputs token forge** (weak invite/reset tokens): when a token is `f(mt_srand(seed(known_inputs, CONST)); mt_rand())` and the seed derives from attacker-known values (email length/chars) plus one unknown constant, you don't need 624 outputs -- recover `CONST` offline from **ONE leaked (input, output) pair** (often disclosed in a log/`/logs/app.log`) by brute-forcing `CONST` locally until the pair reproduces, then forge tokens for any other user. Replicate the target's PRNG exactly: **PHP's `mt_rand` is stable across 7.1+**, so PHP 8 cli reproduces a PHP 7.x target. (THM Decryptify: `seed=hexdec(strlen(email)+CONST+hexdec(substr(email,0,8)))`, one log line gave the pair, `CONST=99999` fell out, forged any invite code.)

### ECC / signatures
- **ECDSA nonce reuse** (same `k` for two sigs) -> recover private key algebraically. Predictable/biased `k` -> lattice (LLL) attack. Invalid-curve / small-subgroup -> recover key mod small primes (CRT).

### Classical / encoding
- Caesar/Vigenere/substitution -> `dcode.fr`, CyberChef, frequency analysis. XOR -> `xortool -c ' '`. Encoding chains -> [[encoding-transformations]].

## Bypasses and variants
- Multi-layer: base64 -> XOR -> RSA. Always re-`file`/entropy-check decoded output.
- Custom hash/cipher: model in `z3` or `sage` and solve symbolically.

## Detection and defence
Use vetted libraries (libsodium); authenticated encryption (AES-GCM with unique nonces); constant-time comparison; CSPRNG (`secrets`, `/dev/urandom`); RSA-OAEP not textbook RSA; reject reused nonces.

## Tools
`RsaCtfTool`, `sage`, `factordb`, `hashpump`, `xortool`, `padbuster`, CyberChef, `z3`, `randcrack`. Hash cracking: [[hashcat]], [[password-cracking]].

## Sources

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[crypto]]
