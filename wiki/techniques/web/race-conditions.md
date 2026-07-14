---
title: "Race Conditions"
type: technique
tags: [exploitation, h1, portswigger, race-condition, thm, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [ps-indepth-race-conditions, ps-labs-race-conditions, thm-adv-race-conditions, h1-scraped-race-conditions, payloadsallthethings-race-condition, git-portswigger-all-labs]
---

# Race Conditions

## What it is

A race condition vulnerability occurs when an application performs a multi-step operation — check, then act — without atomically locking the resource between steps. An attacker who sends multiple requests simultaneously can exploit the brief window between the check and the update to cause unintended behaviour, such as applying a discount code multiple times or bypassing a rate limit.

## How it works

Consider a one-time discount code:

1. Server checks: "Has this coupon been used?" → No
2. Server applies discount to order
3. Server updates database: "Coupon is now used"

Between steps 1 and 3, there is a **race window** — a temporary sub-state where the coupon is considered unused by concurrent requests. If two requests both pass step 1 before either completes step 3, both apply the discount.

This is a subtype of **Time-Of-Check to Time-Of-Use (TOCTOU)** flaws. The state is correct before and after the window; it is only during processing that it is inconsistently applied.

## Prerequisites

- A single-use, rate-limited, or quantity-constrained endpoint with a security or business-logic impact
- The server processes the check and update non-atomically (e.g., in application code rather than a single DB transaction)
- Ability to send requests with sub-millisecond timing differences

## Methodology

### 1. Identify target endpoints

Look for actions with enforced limits:

- Applying a coupon or promo code
- Redeeming a gift card
- Rating a product
- Transfer or withdrawal endpoints
- Login endpoints with a rate limit (failed attempt counter)
- CAPTCHA or one-time token consumption
- Like/vote buttons

### 2. Confirm the state is server-side and session-keyed

Send a request with and without your session cookie to confirm the state is stored server-side. This implies requests sharing a session can collide.

### 3. Benchmark normal behaviour

1. Apply the coupon once — confirm it succeeds
2. Apply it a second time — confirm it is rejected with "already applied"
3. This establishes what a successful race looks like vs. a rejected attempt

### 4. Send parallel requests with Burp Repeater

Burp Suite 2023.9+ supports native single-packet attack mode:

1. Send the target request to Repeater
2. Duplicate it multiple times (Ctrl+R many times)
3. Group all tabs: right-click → "New group" → add all requests
4. Send group in parallel: "Send group (parallel)" or "Send group (single-packet attack)"

For HTTP/2 targets, Burp uses the single-packet attack (all requests in one TCP packet, nullifying network jitter). For HTTP/1, it uses last-byte synchronisation.

**PortSwigger Lab 1 — Limit overrun (coupon):**

1. Add an item to cart and apply the promo code
2. Send `POST /cart/coupon` to Repeater 20 times
3. Group and send in parallel
4. Refresh the cart — multiple discounts applied

### 5. Rate limit bypass via racing (Turbo Intruder)

When a login endpoint locks after N failed attempts, race all password guesses simultaneously before the counter increments:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )
    
    passwords = wordlists.clipboard   # paste candidate passwords from clipboard
    
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    engine.openGate('1')   # send all simultaneously


def handleResponse(req, interesting):
    table.add(req)
```

All login attempts arrive at the server within the same TCP packet (HTTP/2 single-packet attack), so the rate limiter's attempt counter may not increment before most are processed.

**PortSwigger Lab 2 — Rate limit bypass:**

1. Find the login endpoint that blocks after too many attempts
2. Copy candidate passwords to clipboard
3. Use the Turbo Intruder script above (available as a template in the BApp Store)
4. Send — one password should succeed before the lockout takes effect

### 6. Turbo Intruder — general parallel attack

For any high-concurrency race condition attack:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2   # requires HTTP/2
    )
    
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    engine.openGate('1')
```

Key configuration:
- `engine=Engine.BURP2` — enables single-packet attack (HTTP/2 required)
- `concurrentConnections=1` — all requests on the same connection
- `gate` — groups requests; `openGate` releases them simultaneously

Download the latest version from the BApp Store.

### 7. Confirm the exploit

After sending parallel requests, inspect responses:

- Multiple `200 OK` for what should be a single-use action indicates a successful race
- Price drops below expected minimum
- Multiple items in an account that should be limited to one

For the coupon lab: if the order total is still above your store credit, reset and retry (race windows are probabilistic — not every attempt wins).

### 8. Multi-endpoint race conditions

Some race conditions require colliding requests across two different endpoints that share server-side state. The attack races an "add item" against a "checkout" to purchase an item that was not in the cart at the time of payment.

**Collision prediction heuristic:**
1. Is the endpoint security-critical or business-logic critical?
2. Do the two endpoints operate on the same server-side record (same session, same user ID, same cart)?

If both answers are yes, the endpoints are candidates for a multi-endpoint race.

**Connection warming** — before timing multi-endpoint requests, send one or more inconsequential GET requests (e.g., `GET /`) on the same connection to pre-establish it. This separates backend connection-setup latency from endpoint processing time and improves race window alignment.

In Burp Repeater: add a `GET /` tab at the start of the group, then send the group in sequence on a single connection to warm up, then send the attack group in parallel.

**Lab 3 technique (cart checkout race):**

1. Confirm `GET /cart` returns different results with and without session cookie (state is server-side — collision is possible)
2. Build a Repeater group with `POST /cart` (add jacket, productId=1) and `POST /cart/checkout`
3. Ensure only the cheaper item (gift card) is in the cart before sending
4. Send group in parallel — checkout fires while the jacket is being added, purchasing both

### 9. Single-endpoint session-state collision (password reset / email change)

When a single endpoint stores intermediate state in the session, two parallel requests with different parameters can collide, causing the session to contain a mismatched pair (e.g., victim's username + attacker's token).

**Attack pattern (email change hijack):**

1. Trigger an email-change request for `attacker@exploit.com` — observe that a confirmation link is sent
2. Duplicate the request; set Tab 1 to `attacker@exploit.com`, Tab 2 to `victim@target.com`
3. Send both in parallel
4. The server writes the victim's email into the session but sends the confirmation link to the attacker
5. Clicking the attacker's link confirms the victim's address

**Aligning race windows when connection warming fails:** send a large number of dummy requests to trigger server-side rate or resource limits; this forces the server to process subsequent requests sequentially within that degraded state, improving timing alignment.

### 10. Time-sensitive token attacks

When a server generates security tokens using a high-resolution timestamp rather than a cryptographically random value, two requests submitted simultaneously may produce identical tokens.

**Attack pattern (password reset token collision):**

1. Trigger a password reset for `wiener` — note the token in the email
2. Obtain a fresh session + CSRF token (send `GET /forgot-password` without cookie)
3. Build a Repeater group with two `POST /forgot-password` requests — one for `wiener` (using fresh session), one for `carlos` (using your session)
4. Send both in parallel — if the same timestamp is used, both receive the same token
5. Use `wiener`'s token (received in email) to reset `carlos`'s password

Key indicator: if the parallel responses arrive at nearly the same time (low response-time delta), the server is processing them on the same thread and the timestamp seed is shared.

### 11. Partial construction race conditions

Applications that initialise objects in multiple steps create a temporary "partially constructed" state that can be exploited. Example: user registration that creates the DB row before generating the API key means there is a window where the key field is NULL.

**Attack pattern (registration confirmation bypass):**

Use a PHP-style empty array parameter to match the uninitialised NULL value in the database:

- `token[]=` in PHP is equivalent to passing an empty array; if the server compares this to a NULL/unset token with loose equality, the check passes

**Turbo Intruder script for partial construction (register + confirm race):**

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: phpsessionid=YOUR-SESSION-TOKEN
Content-Length: 0
'''
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'User' + currentAttempt
        # One registration request per gate
        engine.queue(target.req, username, gate=currentAttempt)
        # 50 confirmation requests hit while registration is still completing
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```

The gate ensures all 51 requests (1 register + 50 confirm) are released simultaneously. One confirm request will arrive during the window after the user row is created but before the token is written.

**Session-based locking bypass:** Some frameworks (e.g., PHP native session handler) process only one request per session at a time. If requests appear sequential even when sent in parallel, switch to using different session tokens for each request to bypass the per-session lock.

## Key payloads / examples

### Burp Repeater — group parallel send

1. `POST /cart/coupon` — duplicate 20 times
2. Group all
3. Send group in parallel

### Turbo Intruder — single-packet attack template

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2)
    
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```

## Bypasses and variants

| Variant | Description |
|---|---|
| Limit overrun | Send N identical requests in parallel; N-1 extra successes if window is wide enough |
| Rate limit bypass | Send all guesses at once before counter increments |
| Gift card double-redeem | Race the redemption endpoint |
| File upload race | Upload malicious file, access it before validation removes it |
| Multi-endpoint race | Race across two different endpoints sharing session state (e.g., add item + checkout) |
| Single-endpoint session collision | Two parallel requests with different params collide in shared session state (e.g., email change / password reset) |
| Partial construction | Race a confirmation request against a registration before token initialisation completes; match NULL with `param[]=` |
| Time-sensitive token | Trigger two resets simultaneously; timestamp-seeded tokens may be identical, giving attacker victim's token |
| Session-lock bypass | Use different session cookies per request to bypass per-session serialisation in frameworks like PHP |
| Time-based detection | Observe response time differences to infer internal state transitions |

## Real-World Examples (HackerOne — paid reports)

The following reports are drawn from all 11 paid HackerOne race-condition disclosures (2 critical, top bounty $15,250). They cover the full spectrum: web-application limit overruns, blockchain faucet draining, system-level TOCTOU in standard libraries, and verification bypass.

### Shopify partner email confirmation bypass — store takeover ($15,250 critical — Shopify, #300305)

Shopify's partner onboarding flow sent an email confirmation link to verify that a new partner's email was legitimately theirs. The confirmation endpoint did not atomically mark the token as consumed — it checked validity, granted store access, and then marked the token used in three separate, non-locked operations. By sending a burst of simultaneous confirmation requests before the token was invalidated, the researcher confirmed the same token multiple times, each confirmation granting access to a different store. The attacker could use any employee email address to claim access to stores that email was associated with. Executed via parallel HTTP requests (Burp Repeater group send). **Resource:** email-confirmation token (single-use). **Impact:** full store account takeover at scale.

### Cosmos blockchain faucet race — unlimited token drain ($5,000 critical — Cosmos, #1438052)

The Cosmos testnet faucet — which gives out small amounts of test tokens — performed a rate-limit check before dispensing, but the check and the dispense were not atomic. By opening many parallel WebSocket connections via Starport and calling the dispense function simultaneously, the researcher drained the faucet far beyond the per-address limit. **Resource:** test-token balance. **Execution:** concurrent WebSocket/RPC calls. **Takeaway:** blockchain faucets and on-chain operations with rate limits must use atomic nonce checks or commit-reveal patterns; the "check then act" pattern is especially dangerous in async/concurrent blockchain contexts.

### Rust std::fs::remove_dir_all() TOCTOU ($4,000 high — Internet Bug Bounty, #1520931)

The Rust standard library's `remove_dir_all()` function performed a check-then-use (TOCTOU) sequence: it checked that the target path was a directory, then recursively deleted contents, then removed the directory — with no atomic lock between operations. An attacker on the local system could race a symlink swap between the check and the deletion, tricking `remove_dir_all()` into deleting an arbitrary directory tree outside the intended path. **Resource:** filesystem directory path. **Execution:** concurrent thread replacing the directory with a symlink. **Takeaway:** filesystem operations that check a path type before acting on it must use file descriptors (open once, operate via descriptor) rather than path strings to eliminate the TOCTOU window.

### World ID verification bypass ($3,000 high — Tools for Humanity, #2110030)

The Worldcoin World ID verification endpoint enforced a "one verification per person" rule, but the uniqueness check and the verification write were non-atomic. By submitting two verification attempts simultaneously (parallel POST requests), the researcher bypassed the check and created multiple valid World ID verifications for the same identity. **Resource:** verification slot (one per person). **Execution:** Burp Repeater parallel group send. **Takeaway:** identity verification systems must use database unique constraints enforced at the write layer, not application-level checks — a `UNIQUE` constraint with an `INSERT ... ON CONFLICT IGNORE` pattern makes the race impossible.

### curl fopen() race condition — CVE-2023-32001 ($2,480 medium — Internet Bug Bounty, #2078571)

libcurl's cookie-jar write path opened a file, checked whether it was a regular file, and then wrote to it — with a TOCTOU gap between the check and the write. On a shared system, another process could replace the regular file with a symlink between the check and the write, redirecting curl's cookie output to an arbitrary path writable by the user's permissions. **Resource:** filesystem path. **Execution:** concurrent symlink swap. **Takeaway:** file operations in security-sensitive paths (cookie files, credential caches) should use `O_NOFOLLOW` and `fstat()` on the opened descriptor rather than separate `stat()`-then-`open()` sequences.

### HackerOne CTF group membership race ($500 low — HackerOne, #1540969)

HackerOne CTF events allowed a limited number of participants per group. The join-group endpoint checked the current member count and added the user in two separate operations. By racing multiple join requests simultaneously, a user could join the same group more than the allowed count, exceeding the capacity limit. **Resource:** group-member slot. **Execution:** Burp Repeater parallel send. **Takeaway:** capacity-constrained group-join operations must use an atomic increment with a cap (e.g., `UPDATE groups SET count = count + 1 WHERE count < max RETURNING count`) rather than a check-then-insert pattern.

### Chaturbate subdomain limit bypass ($100 low — Chaturbate, #395351)

Chaturbate enforced a per-account subdomain registration limit in application code with a check-then-insert pattern. Racing multiple subdomain-creation requests simultaneously allowed the researcher to create more subdomains than the account limit permitted. **Resource:** subdomain allocation slot. **Execution:** concurrent POST requests. **Takeaway:** enforcement of per-account resource limits must happen at the database constraint level (a count enforced in a single atomic transaction), not by reading the current count and conditionally inserting.

## Detection and defence

- **Atomic database operations**: Implement check-and-update in a single atomic transaction with row locking (e.g., `SELECT ... FOR UPDATE` in SQL)
- **Idempotency keys**: Generate a unique token for each action; mark it as consumed atomically before performing the action
- **Distributed locks**: Use Redis `SET NX` or similar to acquire a lock before the critical section
- **Rate limiting with sliding windows**: Use an atomic counter (Redis `INCR`) rather than a read-check-write cycle
- **No application-layer TOCTOU**: Never separate "check if allowed" from "perform action" into two sequential non-locked DB queries

## Tools

- [[burp-suite]] — Repeater with group parallel send, single-packet attack mode (HTTP/2)
- Turbo Intruder — BApp Store extension for high-concurrency attacks with Python scripting
- Raceocat — https://github.com/JavanXD/Raceocat — highly efficient CLI tool for exploiting web race conditions
- h2spacex — https://github.com/nxenon/h2spacex — HTTP/2 Single Packet Attack low-level library based on Scapy
- Custom scripts — `requests` + `ThreadPoolExecutor` for internal port enumeration races

## PortSwigger Labs

### Lab 1 — Limit overrun race conditions (Apprentice)

Exploit a non-atomic coupon redemption endpoint to apply a single-use promo code multiple times.

**Method A (Burp Intruder):**
1. Send `POST /cart/coupon` to Intruder; set null payload, count 30; configure resource pool for 30 concurrent requests
2. Run attack — multiple requests succeed before the server marks the code used

**Method B (Burp Repeater parallel group):**
1. Remove the coupon to reset state
2. Send `POST /cart/coupon` to Repeater; duplicate tab 50 times (Ctrl+R)
3. Group all tabs; send group in parallel
4. Refresh cart — discount stacks beyond 20%

---

### Lab 2 — Bypassing rate limits via race conditions (Practitioner)

Brute-force login past a lockout limit by sending all password guesses simultaneously.

**Method A (Burp Intruder):**
1. Set username to `carlos`, payload position on password field
2. Resource pool: 30 concurrent requests
3. A `302` response indicates the correct password was found before lockout

**Method B (Turbo Intruder — single-packet attack):**
1. Send login request to Turbo Intruder; select "Single Packet Attack" template
2. Use `%s` as payload position on the password parameter
3. Paste password list; click Attack — `302` response reveals the valid password

---

### Lab 3 — Multi-endpoint race conditions (Practitioner)

Race `POST /cart` (add expensive item) against `POST /cart/checkout` so checkout processes before the cart is updated.

1. Confirm cart state is server-side: `GET /cart` without cookie returns empty cart
2. Place only the cheap item (gift card) in cart
3. Build Repeater group: Tab 1 = `POST /cart` with `productId=1` (jacket), Tab 2 = `POST /cart/checkout`
4. Send group in parallel — checkout races the add; jacket gets purchased at gift-card price
5. If jacket not purchased, reset (add gift card only) and retry

---

### Lab 4 — Single-endpoint race conditions (Practitioner)

Race two parallel email-change requests from the same session to cause a session-state collision, hijacking a confirmation link to change a target account's email.

1. Send `POST /change-email` to Repeater; duplicate into two tabs
2. Tab 1: `email=attacker@exploit.com`, Tab 2: `email=carlos@ginandjuice.shop`
3. Group both; send in parallel
4. The confirmation link sent to the attacker's inbox may confirm the `carlos@ginandjuice.shop` address (session holds victim email but token goes to attacker)
5. Repeat until the race succeeds; clicking attacker's link grants admin email — delete `carlos` account

---

### Lab 5 — Exploiting time-sensitive vulnerabilities (Practitioner)

Exploit timestamp-seeded password reset tokens: two simultaneous resets for different users generate the same token.

1. Request a password reset for `wiener` — note token format
2. Send `GET /forgot-password` without cookie to get a fresh session + CSRF token
3. Build Repeater group: two `POST /forgot-password` requests — one uses fresh session (username=`carlos`), one uses original session (username=`wiener`)
4. Send in parallel — minimal response time delta confirms shared timestamp seed
5. `wiener`'s token (received in attacker's email) is valid for `carlos` — use it to reset `carlos`'s password
6. Retry until token is accepted (probabilistic — not every attempt produces the same timestamp)

---

### Lab 6 — Partial construction race conditions (Expert)

Exploit the window between user row creation and token initialisation during registration to confirm an account with a NULL/empty token via PHP's loose-comparison `token[]=` trick.

1. Attempt to register — only `@ginandjuice.shop` emails accepted; note the `/confirm?token=` endpoint
2. Test token values: random token → "Invalid token"; no token → "Forbidden"; `token[]=` → "Invalid Array" (server accepts array, does DB comparison)
3. Send registration request to Turbo Intruder; use the partial construction script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: phpsessionid=YOUR-SESSION-TOKEN
Content-Length: 0
'''
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'User' + currentAttempt
        engine.queue(target.req, username, gate=currentAttempt)
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```

4. Set `%s` on the username field; run attack — one `User<N>` account gets confirmed when a confirm request lands during the NULL-token window
5. Log in with the confirmed account; delete `carlos`

**Key insight:** PHP compares `[]` (empty array) to `NULL` as truthy with `==` loose equality. Use `param[]=` to match an uninitialised database field.

---

## Sources

- PortSwigger Academy — Race Conditions (In-depth)
- PortSwigger Labs 1–6: Limit overrun, Rate limit bypass, Multi-endpoint, Single-endpoint, Time-sensitive, Partial construction
- THM Advanced Web — Race Conditions room (`raceconditionsattacks`)
