---
title: "Business Logic Vulnerabilities"
type: technique
tags: [business-logic, h1, web]
phase: exploitation
date_created: 2026-05-08
date_updated: 2026-05-13
sources: [h1-scraped-business-logic, payloadsallthethings-businesslogic, git-portswigger-all-labs]
---

## What it is

Vulnerabilities in the application's intended workflow — the logic that governs what actions are allowed, in what order, and under what conditions. Unlike injection bugs, these require understanding the application's purpose and abusing valid features in unintended ways.

## How it works

Business logic flaws arise when developers implement rules that can be circumvented by manipulating state, sequence, or parameters outside the expected flow: skipping workflow steps, replaying transactions, manipulating prices/quantities, abusing referral/coupon systems, or bypassing payment verification.

## Attack phases

Exploitation — requires understanding the application's purpose and normal user flow.

## Prerequisites

- Account on the target application
- Understanding of the intended business workflow

## Methodology

1. Map the full workflow for high-value features (checkout, subscription, referral, file sharing)
2. Identify state-dependent transitions — can you skip steps?
3. Test negative/zero/fractional quantities in cart/payment flows
4. Apply discount codes multiple times or in combination
5. Intercept and replay confirmation/activation requests
6. Test concurrent requests on single-use actions (see [[race-conditions]])

### Specific Feature Testing Strategies

- **Review Feature Testing:** Post reviews without purchasing, test out-of-bounds ratings (0, 6, negative), race conditions for multiple reviews, impersonate users.
- **Discount Code Testing:** Apply same code multiple times, use race conditions for two accounts simultaneously, test mass assignment to apply multiple codes, apply to non-discounted items.
- **Delivery Fee Manipulation:** Negative delivery charges, modify parameters to activate free delivery.
- **Currency Arbitrage:** Pay in one currency (e.g., USD) and request refund in another (e.g., EUR) to exploit conversion rate differences.
- **Premium Feature Exploitation:** Purchase premium, cancel/refund, and check if still accessible. Fuzz true/false values validating premium access.
- **Cart/Wishlist Exploitation:** Add products in negative quantities to balance total, add more than available, move items between users' carts.
- **Rounding Errors:** Exploit internal transfer precision (e.g. initiating 0.5 satoshi transfer where sender rounds down to 0 and receiver rounds up to 1 satoshi).

### Client-Side Trust Exploitation

When an "add to cart" or similar request passes price or critical values as client-controlled POST parameters, modify them directly:

```http
POST /cart HTTP/1.1
...
productId=1&redir=PRODUCT&quantity=1&price=1
```

The server must never accept a price value from the client — it should look up the canonical price server-side.

### Integer Overflow / Negative Quantity Abuse

Applications that store totals as bounded integers (e.g., 32-bit signed) can be forced to wrap to negative values by adding quantity=99 in a loop. Use Burp Intruder with Null payloads (Continue Indefinitely) to overflow the cart total past zero and into negative territory, then fine-tune quantity to land the total in the affordable range.

```
Intruder: Sniper | Null payloads | Continue indefinitely
Target request: POST /cart with quantity=99
Stop when: cart total goes negative, then adjust final quantity
```

### Coupon Alternation Attack

If the application tracks "last applied coupon" rather than a set of applied coupons, alternating between two different codes defeats the duplicate-check:

1. Apply promo code → accepted.
2. Apply newsletter code → accepted.
3. Re-apply promo code → accepted again (server only checks against the most-recently-applied code).
4. Repeat until price reaches zero or near zero.

### Workflow Step Skip

Map the happy-path request sequence. After completing a cheaper purchase to observe the full flow, replay the order-confirmation GET request directly for a more expensive cart:

```http
GET /cart/order-confirmation?order-confirmed=true HTTP/1.1
```

If the server issues the confirmation without re-validating payment, the item is purchased for free.

### Flawed State Machine — Default Privilege Assignment

During multi-step login or onboarding, drop or intercept an intermediate request (e.g., a `GET /role-selector` that lets the user choose their role). If the application defaults to the highest privilege when that step is skipped, the attacker lands with admin rights.

```
1. Submit login credentials → receive session cookie
2. DROP the GET /role-selector follow-up request (do not forward)
3. Navigate to /admin — application may grant admin by default
```

### Dual-Use Endpoint — Missing Parameter Validation

Password-change endpoints that determine the target account from a `username` request parameter rather than from the authenticated session allow account takeover:

```http
POST /my-account/change-password HTTP/1.1
...
csrf=TOKEN&username=administrator&new-password-1=pwned&new-password-2=pwned
# current-password parameter omitted entirely — server accepts the change
```

### Infinite Money via Coupon + Gift Card Loop

When a signup discount can be applied to a gift-card product whose redemption value exceeds the discounted purchase price, a net-positive credit loop is possible. Automate with Burp Macros:

```
Macro sequence:
  POST /cart                         (add gift card)
  POST /cart/coupon                  (apply SIGNUP30 or equivalent)
  POST /cart/checkout
  GET  /cart/order-confirmation?order-confirmed=true   (extract gift-card code)
  POST /gift-card                    (redeem extracted code)

Intruder: Sniper | Null payloads | N iterations until balance >= target price
```

### Email Truncation for Domain Bypass

If the backend truncates email addresses to a fixed length (commonly 255 chars) after validation but before storing, craft an address whose real domain is beyond the truncation point:

```
# Structure: <padding>@target-domain.com.<attacker-domain>
# Length: padding + @target-domain.com = exactly 255 chars
# After truncation: stored email ends with @target-domain.com
# Confirmation sent to: attacker@<attacker-domain>

Example (299-char input, 255-char stored):
aaa...aaa@dontwannacry.com.exploit-server.net
                            ^--- truncated here at char 255
```

Steps:
1. Register with oversized email — receive confirmation at attacker domain.
2. Click confirmation link.
3. Log in — stored email now ends with the privileged domain, granting access.

### Encryption Oracle for Cookie Forgery

When the same symmetric cipher is used for both a `stay-logged-in` cookie (`username:timestamp`) and a user-visible notification cookie (`Invalid email address: <input>`), the notification endpoint acts as an encryption oracle:

1. Submit `administrator:<timestamp>` as the email field in a comment/notification form.
2. Retrieve the `notification` cookie — it is the AES-CBC encryption of `Invalid email address: administrator:<timestamp>`.
3. Remove the known prefix (`Invalid email address: ` = 23 bytes). Pad with 9 bytes to align to a 16-byte block boundary, then strip the first two 16-byte blocks (32 bytes total).
4. The remaining ciphertext decrypts to `administrator:<timestamp>` — use it as the `stay-logged-in` cookie to authenticate as administrator.

```
Prefix length: 23 bytes ("Invalid email address: ")
Block size:    16 bytes (AES-128-CBC inferred from error on single-byte input)
Padding needed: 9 bytes → first two blocks (32 bytes) = prefix + padding
Strip first 32 bytes of the ciphertext → remainder = encrypted(administrator:<ts>)
```

### Email Address Parsing Discrepancies

Different application layers (validation, email routing, storage) may parse RFC 5322 constructs differently. Techniques to exploit parsing gaps:

- **Encoded-word / charset injection:** Use UTF-7 encoded `@` (encoded as `&AEA-`) to embed a second `@` that the validator does not see but the mail server resolves.
```
=?utf-7?q?user&AEA-attacker@exploit-server.net&ACA-?=@target-domain.com
# Validator sees: ...@target-domain.com (passes domain check)
# Mail server routes to: attacker@exploit-server.com
```
- **Quoted local-part:** `"@"@example.com` — the `@` inside quotes is a literal character per RFC 5322 but may confuse parsers.
- **Comments:** `(comment)user@(comment)example.com` — valid per RFC but inconsistently handled.
- **Email truncation:** see section above.

## Real-World Examples (HackerOne — paid reports)

The following reports are drawn from 65 paid HackerOne disclosures (5 critical, top bounty $12,000). They illustrate the core business-logic failure classes: payment manipulation, privilege-bypass on gated workflows, coupon/discount reuse, and OTP/state confusion.

### Pipeline jobs executed as arbitrary user ($12,000 critical — GitLab, #894569)

GitLab's CI/CD pipeline runner respected a user-supplied identity parameter without validating that the authenticated caller was permitted to impersonate that identity. An attacker could trigger a pipeline job that ran with the privileges of any other GitLab user — including project maintainers and owners — by setting the runner identity to the target. **Takeaway:** workflow orchestration systems that accept an "execute as" parameter must independently verify authorization for each identity substitution, not just the caller's own session.

### Double payout via PayPal ($10,000 critical — Coinbase, #307239)

Coinbase's PayPal withdrawal flow did not atomically lock the payout state before dispatching the PayPal API call. By triggering a payout and immediately initiating a second payout for the same funds before the first was confirmed, the researcher received two payouts for a single balance deduction. This is a classic transaction-integrity flaw: the application assumed the first request would complete before a second could be submitted. **Takeaway:** payment initiation must use database-level locking or idempotency keys to prevent concurrent submissions draining the same balance.

### In-flight payment data modification to Smart2Pay ($7,500 critical — Valve, #1295844)

Valve's checkout integration with the Smart2Pay provider passed payment parameters through the client in a way that an attacker could intercept and modify before they reached the payment gateway. The researcher altered transaction amounts in-flight, completing purchases for a fraction of the actual price. **Takeaway:** payment parameters (amount, currency, order ID) must be generated server-side and communicated directly to the payment provider; they must never pass through the client in a mutable form.

### Zomato Gold unlocked via arbitrary wallet ID ($2,000 critical — Eternal/Zomato, #938021)

The Zomato Gold subscription-activation endpoint accepted a `wallet_id` parameter without validating ownership. By substituting a `wallet_id` belonging to another user, the researcher activated a premium Gold subscription on their account funded by the victim's wallet. **Takeaway:** financial and subscription endpoints must verify that the wallet/payment source identifier in the request belongs to the authenticated session; never trust client-supplied resource identifiers for billing.

### Phone-number takeover via OTP state confusion ($2,000 critical — inDrive, #2588329)

The "change phone number" flow issued an OTP to the new number but did not bind the OTP validation step to the original session. By initiating the change for one number and then submitting the OTP in a separate request with a different target number, the attacker could validate OTPs against arbitrary phone numbers — effectively taking over any account by number. **Takeaway:** OTP validation must be bound to the exact session state that requested it; the validated identifier must be locked at initiation, not re-read from the request at confirmation.

### Reddit ad-approval status bypass ($5,000 high — Reddit, #1543159)

Reddit's advertising workflow required payment details to be on file before an admin could approve an ad campaign and set it to "effective" status. The researcher found they could call the approval endpoint directly, bypassing the payment-verification prerequisite. The application enforced the workflow in the UI but not in the API. **Takeaway:** all workflow preconditions (payment verified, identity confirmed, review passed) must be enforced server-side on every state-transition endpoint, regardless of how the UI controls access.

### Fee discount redeemed unlimited times ($5,000 medium — Stripe, #1849626)

Stripe's fee-discount system recorded redemption in a non-atomic way. The researcher could race simultaneous redemption requests (see [[race-conditions]]) or exploit a flag-reset bug to apply a single-use fee discount an unlimited number of times, generating effectively free transactions. **Takeaway:** single-use promotional codes and discounts must be invalidated atomically at first redemption using a database transaction with a unique constraint; rate-limiting alone is insufficient.

### SteamGuard brute force — account takeover ($2,500 high — Valve, #407971)

Steam's account-recovery flow on `help.steampowered.com` accepted SteamGuard codes without enforcing a rate limit or attempt counter that matched the UI. The researcher brute-forced the numeric code space offline and submitted codes in bulk, bypassing the "only three attempts" policy shown in the UI. **Takeaway:** attempt counters for OTPs and guard codes must be enforced server-side with hard rate limits and lockout independent of any UI affordance.

### Wallet top-up with arbitrary amount ($2,000 high — Eternal, #1408782)

The wallet top-up endpoint accepted the amount parameter from the client body without re-validating it against the payment-gateway confirmation. The researcher modified the amount to a minimal value (₹1) while the server credited the full requested amount (₹10,000). **Takeaway:** never credit a wallet or account based on a client-supplied amount; the amount to credit must be read from the payment-gateway callback's confirmed transaction value, not from the original client request.

### GitLab domain hijacking via pages workflow ($750 high — GitLab, #312118)

GitLab Pages allowed a user to claim custom domains by verifying a DNS TXT record. The verification state was not re-checked after initial setup. When a legitimate domain owner deleted their GitLab project, the domain-to-project binding was not cleaned up. A new attacker project could then claim the same domain, effectively hijacking it. **Takeaway:** resource bindings (domain-to-project, email-to-account) must be re-validated on deletion and re-association; stale claims must be explicitly released.

### HackerOne private-invite harvesting ($2,500 medium — HackerOne, #334205)

HackerOne's "leave program" fast-track re-invitation feature forwarded a copy of private-program invites to a security@ email alias if that alias was configured on the researcher's account. By setting the alias to an address the researcher controlled and then triggering the leave/re-invite flow, they received private program invitations intended for other researchers. **Takeaway:** invitation and notification workflows must validate that the recipient address is the one associated with the intended target account; forwarding or alias features must not be permitted to redirect privileged communications to third-party addresses.

## Detection and Defence

- Enforce all workflow preconditions server-side on every state-transition endpoint, not just in the UI
- Use database-level transactions with unique constraints for single-use codes, OTPs, and payment initiations
- Never trust client-supplied amounts, identities, or resource identifiers for financial or privilege operations
- Bind OTP and token validation to the session state present at initiation time
- Re-validate resource ownership on every request that references a billable or privileged resource
- Audit state-machine transitions for unreachable-from-UI paths that remain accessible via direct API calls
- Test concurrent requests on all single-use or quota-enforced actions (see [[race-conditions]])

## PortSwigger Labs

### Apprentice

### Lab 1 — Excessive trust in client-side controls

The `POST /cart` request includes a `price` parameter supplied by the client. Intercept the request and set `price=1` (or any low value). The server accepts the manipulated price and the item is added at that cost. Place the order to complete the purchase.

**Flaw class:** Client-side parameter trust — server never re-validates price against its own catalogue.

### Lab 2 — High-level logic vulnerability

The `POST /cart` request includes a `quantity` parameter. Setting `quantity` to a large negative number (e.g., `-145`) causes the server to subtract the absolute value from the cart total, reducing it to an affordable amount.

```
POST /cart
quantity=-145   → total drops from $1337 to ~$31.40
```

**Flaw class:** No lower-bound validation on quantity — negative values not rejected.

### Lab 3 — Inconsistent security controls

The admin panel at `/admin` is restricted to `@dontwannacry.com` email addresses. A registered user can update their email to `anything@dontwannacry.com` post-registration (no re-verification required), immediately granting admin access.

**Flaw class:** Trust boundary inconsistency — email domain checked at registration but not re-verified on update; domain-based access control is trivially bypassed by self-service email change.

### Lab 4 — Flawed enforcement of business rules

The application has two valid discount codes (a promo code and a newsletter signup code). Applying the same code twice is blocked ("Coupon already applied"), but the check is against the most-recently-applied code only. Alternating between the two codes repeatedly allows infinite stacking:

1. Apply promo code → accepted.
2. Apply newsletter code → accepted.
3. Re-apply promo code → accepted (last-applied was newsletter).
4. Repeat until price reaches zero.

**Flaw class:** Coupon deduplication tracks last-applied rather than the full set of applied codes.

---

### Practitioner

### Lab 5 — Low-level logic flaw

The server stores cart totals in a bounded signed integer. Repeatedly adding `quantity=99` using Burp Intruder (Null payloads, Continue Indefinitely) causes the total to overflow past the maximum and wrap to a negative value. Adjust the final quantity to bring the total into a range that can be covered by store credit.

```
Intruder setup:
  Attack type: Sniper
  Payload type: Null payloads → Continue indefinitely
  Position: none (base request unmodified, quantity=99 in body)
Stop when: cart total wraps negative
Fine-tune: add/remove items to reach affordable total
```

**Flaw class:** Integer overflow — no guard on cumulative cart total.

### Lab 6 — Inconsistent handling of exceptional input

The `/admin` panel is restricted to `@dontwannacry.com` addresses. The backend truncates email addresses to 255 characters at storage time. Craft a registration email that is longer than 255 characters, where the substring at position 0–254 ends with `@dontwannacry.com`, and the full email (beyond 255 chars) points to an attacker-controlled domain for delivery:

```
Structure: <239-char padding>@dontwannacry.com.<attacker-domain>
                              ^--- position 255 boundary
After truncation: stored as <padding>@dontwannacry.com
Confirmation delivered to: registrant@<attacker-domain>
```

1. Register with the oversized address — confirmation email arrives at attacker domain.
2. Click the link.
3. Log in — stored email ends with `@dontwannacry.com`, granting admin access.

**Flaw class:** Input truncation applied after validation but before storage creates a discrepancy between the validated and stored values.

### Lab 7 — Weak isolation on dual-use endpoint

The `POST /my-account/change-password` endpoint determines the target account from the `username` body parameter rather than from the authenticated session. The `current-password` parameter is optional — omitting it entirely still succeeds. Send:

```http
POST /my-account/change-password HTTP/1.1
...
csrf=TOKEN&username=administrator&new-password-1=newpass&new-password-2=newpass
```

The administrator password is reset without knowing the current password. Log in as administrator and access `/admin`.

**Flaw class:** Dual-use endpoint allows privilege escalation; missing-parameter validation accepts requests without the required authentication proof.

### Lab 8 — Insufficient workflow validation

The checkout flow normally enforces payment before confirming an order. Observe the full flow with an affordable item: after `POST /cart/checkout` succeeds, the server redirects to `GET /cart/order-confirmation?order-confirmed=true`. This confirmation endpoint does not re-validate that the checkout step was legitimately completed for the current cart. Add the expensive item to the cart, then issue:

```http
GET /cart/order-confirmation?order-confirmed=true HTTP/1.1
```

The server confirms the order without charging.

**Flaw class:** Order-confirmation endpoint does not verify that the preceding payment step completed successfully for the current cart contents.

### Lab 9 — Authentication bypass via flawed state machine

After login, the application issues a follow-up `GET /role-selector` request to let the user choose a role. If this request is **dropped** (not forwarded), the application assigns a default role — which turns out to be `administrator`. The user lands on the home page with a link to the admin panel.

```
1. Submit credentials → intercept GET /role-selector
2. Drop the intercepted request (do not forward)
3. Navigate to /admin → admin access granted by default
```

**Flaw class:** State machine defaults to highest privilege when an expected transition step is skipped.

### Lab 10 — Infinite money logic flaw

A `SIGNUP30` newsletter coupon gives 30% off any item, including gift cards. A $10 gift card bought with SIGNUP30 costs $7 but redeems for $10, netting +$3 per cycle. Automate with a Burp Macro:

```
Macro sequence (run via Session Handling Rules → Run a macro):
  1. POST /cart                        (add gift card productId)
  2. POST /cart/coupon                 (body: coupon=SIGNUP30)
  3. POST /cart/checkout
  4. GET  /cart/order-confirmation?order-confirmed=true   (extract gift-card parameter)
  5. POST /gift-card                   (body: gift-card=<extracted code>)

Intruder: GET /my-account | Sniper | Null payloads | 420 iterations
Result: store credit exceeds $1337 → purchase leather jacket
```

**Flaw class:** Gift-card resale arbitrage — discount code applicable to redeemable-value items creates a net-positive credit loop.

### Lab 11 — Authentication bypass via encryption oracle

The application uses the same AES-128-CBC key for the `stay-logged-in` cookie (`username:timestamp`) and the `notification` cookie (encrypts `Invalid email address: <input>`). The notification endpoint acts as an encryption oracle:

1. Submit `administrator:<timestamp>` as the comment email field — receive `notification` cookie = `Encrypt("Invalid email address: administrator:<timestamp>")`.
2. The known prefix `"Invalid email address: "` is 23 bytes. Add 9 bytes of padding to align to 32 bytes (2 × 16-byte blocks).
3. URL-decode + base64-decode the notification cookie; strip the first 32 bytes.
4. Re-encode (base64 + URL-encode) the remaining ciphertext — this decrypts to `administrator:<timestamp>`.
5. Set this value as the `stay-logged-in` cookie and request `/my-account?id=administrator`.

```
Prefix: "Invalid email address: " = 23 bytes
Padding: 9 bytes (to fill 2 full 16-byte blocks = 32 bytes)
Strip: first 32 bytes of decoded ciphertext
Result: Encrypt(administrator:<timestamp>) → valid stay-logged-in cookie
```

**Flaw class:** Shared encryption key between a user-visible oracle endpoint and an authentication cookie enables forgery of arbitrary cookie values.

---

### Expert

### Lab 12 — Bypassing access controls using email address parsing discrepancies

The registration endpoint restricts accounts to `@ginandjuice.shop` email addresses. Different layers parse RFC 5322 encoded-word syntax differently. UTF-7 encoding is not blocked by the server-side validator but is decoded by the mail delivery layer, splitting the address into two `@` signs:

```
Registration payload:
=?utf-7?q?hanzala&AEA-attacker@exploit-server.net&ACA-?=@ginandjuice.shop

UTF-7 decodes &AEA- → @  and  &ACA- → space
Decoded: hanzala@attacker@exploit-server.net @ginandjuice.shop

Validator sees: ...@ginandjuice.shop → passes domain check
Mail server routes to: attacker@exploit-server.net (first @ wins)
```

Steps:
1. Register with the UTF-7 encoded payload.
2. Receive confirmation at the exploit server; click the link.
3. Log in — account is associated with `@ginandjuice.shop` internally, granting admin access.

**Flaw class:** Email address parsing discrepancy between the validation layer (does not decode UTF-7) and the mail delivery layer (decodes UTF-7), allowing the attacker to control the delivery address while satisfying the domain check.

---

## See also

- [[race-conditions]] — concurrent-request exploitation of single-use resources
- [[access-control]] — IDOR and broken object-level authorisation
- [[authentication-attacks]] — authentication bypass often combined with logic flaws

## Wired sub-techniques

<!-- auto-wired: context-reachable sub-technique pages -->
- [[hpp-attacks]]
