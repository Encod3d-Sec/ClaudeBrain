---
title: "Insecure Randomness"
type: technique
tags: [cryptography, web]
phase: exploitation
date_created: 2026-05-13
date_updated: 2026-05-13
sources: [payloadsallthethings]
---

# Insecure Randomness

## What it is
Insecure randomness refers to weaknesses associated with pseudo-random number generation (PRNG) when used for security-critical purposes like tokens, passwords, or identifiers. Predictable outputs can lead to data breaches or unauthorized access.

## Time-Based Seeds
Many generic RNGs use the current system time as a seed. This approach is highly predictable.
```python
import random
import time
# Vulnerable seeding
seed = int(time.time())
random.seed(seed)
```

## GUID / UUID
UUIDs (Universally Unique Identifiers) are 128-bit numbers.
*   **Version 1**: Based on time/clock sequence and MAC address. Highly predictable. Can be inspected/attacked with `intruder-io/guidtool`.
*   **Version 4**: Randomly generated (secure if underlying RNG is strong).

## Mongo ObjectId
MongoDB ObjectIds are 12 bytes generated predictably:
*   **Timestamp** (4 bytes)
*   **Machine Identifier** (3 bytes)
*   **Process ID** (2 bytes)
*   **Counter** (3 bytes, incrementing)
*   **Tool**: `andresriancho/mongo-objectid-predict` can predict subsequent ObjectIds.

## Uniqid (PHP)
Tokens derived using PHP's `uniqid()` are based on microtime and can be reversed to the exact timestamp using tools like `Riamse/python-uniqid`.

## mt_rand() (PHP)
Breaking `mt_rand()` does not require brute-force if two outputs are known.
*   **Tool**: `ambionics/mt_rand-reverse` recovers the seed.

## Custom Algorithms
Avoid custom randomness like `md5(time())` or sandwich attacks against time-based secrets. Tools like `AethliosIK/reset-tolkien` can exploit insecure time-based secret generation in password resets.
