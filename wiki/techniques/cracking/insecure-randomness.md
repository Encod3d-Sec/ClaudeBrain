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

## Offline brute of a timestamp-seeded reset token (server clock = the oracle)

When source review shows a reset token derived from the server clock - e.g.
`sha1(str(datetime.now())[:-4] + " . " + USERNAME.upper())` - the entropy is only the truncated
timestamp, so the token is computable offline. Python's `str(datetime.now())` is
`YYYY-MM-DD HH:MM:SS.ffffff`; `[:-4]` leaves **centiseconds**, i.e. exactly 100 candidates per
second of clock uncertainty.

You do not need the server's clock leaked in the page: the HTTP `Date` header of the reset
response IS the clock, to the second. Trigger the reset, take `Date`, then test every centisecond
across a small window around it:

```python
srv = email.utils.parsedate_to_datetime(r.headers["Date"]).replace(tzinfo=None)
for off in range(-3, 2):
    base = srv + datetime.timedelta(seconds=off)
    for cs in range(100):
        stamp = base.strftime("%Y-%m-%d %H:%M:%S") + ".%02d" % cs
        cand = hashlib.sha1((stamp + " . " + user.upper()).encode()).hexdigest()
```

~500 candidates, checked concurrently against the validation endpoint, is seconds of work.

Gotchas:
- `datetime.now()` is LOCAL time while `Date` is UTC. If they disagree the window must sweep the
  UTC offset too - check a clock the app renders (`gmtime()` output) against `Date` first.
- The validation endpoint doubles as a **username oracle**: a token only exists for a user the
  app actually found, so "no candidate validates" also means "that username does not exist".
- Confirm the live parameter name before brute-forcing: a distinct error string
  ("Invalid parameter" vs "Invalid token") tells you which name is being read and that the value
  reached a lookup. Leaked dev source may name it differently from production.
- Some implementations hold the token in a module-level global rather than the DB, so it is
  single-slot and one-shot: the newest reset request overwrites the previous token, and a
  successful reset clears it.

<!-- promoted-slug: timestamp-reset-token-offline-brute -->
