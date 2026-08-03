---
title: "Payloads: Crypto Attacks (Quick Arsenal)"
type: payloads
tags: [payloads, crypto, padding-oracle, jwt, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: Crypto Attacks

Fast checks for misused crypto in web tokens/data (OWASP A02). Full theory + tooling: [[cryptography-attacks]]; tokens [[jwt-attacks]].

## Identify the blob
```
rO0AB / AAEAAAD     -> Java/.NET serialized (see deserialization)
base64 of 16-byte multiple, changes wholesale per byte -> ECB ; same prefix blocks repeat -> ECB
"0e" + digits hash  -> PHP magic hash / type juggling (see type-juggling)
eyJ...               -> JWT (see jwt)
hex/IV.ct format     -> CBC -> padding oracle candidate
```

## ECB
```
identical plaintext blocks -> identical ciphertext: rearrange/cut-paste blocks
byte-at-a-time decryption against an encryption oracle (controlled prefix)
flip a role block: encrypt "userrole=adminXXX" -> move the admin block
```

## CBC
```
bit-flipping: XOR ciphertext block C[i-1] to flip chosen bytes of P[i]  (e.g. user=0 -> user=1)
padding oracle: distinct "padding error" vs other error -> padbuster URL ciphertext blocksize -> decrypt/forge
IV in token + IV controllable -> flip first block
```

## Stream / keystream reuse
```
same nonce/IV reused (CTR/OTP): C1 xor C2 = P1 xor P2 -> crib-drag
GCM nonce reuse -> recover auth key -> forge tags
```

## Hash / MAC
```
length extension (H(secret||msg)=sig): hashpump -s sig -d known -a append -k keylen  -> forge MAC
magic hash (== compare): provide "0e..." colliding string (type juggling)
weak/no signature on token: strip/forge
```

## JWT (see jwt for full set)
```
alg:none   weak HS256 secret (hashcat -m 16500)   RS256->HS256 confusion (sign with public key)   kid path/SQLi   jku/x5u SSRF
```

## Real-world
Padding-oracle on a "remember me"/state cookie -> decrypt+forge it; ECB cut-and-paste and CBC bit-flip on home-rolled token crypto; hash length extension on `H(secret||data)` MACs - all recurring real findings on custom auth.
