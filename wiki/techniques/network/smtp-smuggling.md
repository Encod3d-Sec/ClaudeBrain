---
title: "SMTP Smuggling"
type: technique
tags: [network, email, smtp, spoofing, smuggling, desync]
phase: exploitation
date_created: 2026-06-17
date_updated: 2026-06-17
sources: [secconsult-smtp-smuggling, securityweek-smtp-smuggling]
---

# SMTP Smuggling

## What it is
SMTP smuggling (Timo Longin / SEC Consult, 2023) abuses a parsing discrepancy between the outbound (sending) and inbound (receiving) SMTP servers over how the end-of-data sequence is interpreted. An attacker smuggles a second, attacker-controlled email inside the DATA of a legitimately sent message, letting the smuggled message spoof its From as any domain while the carrier message passes SPF, DKIM, and DMARC.

## How it works
SMTP terminates message data with `<CR><LF>.<CR><LF>` (a dot on its own line). Some servers also accept non-standard variants such as `<LF>.<LF>`, `<CR>.<CR>`, or `<LF>.<CR><LF>`. If the outbound server does not treat a variant as end-of-data but the inbound server does (or vice versa), the attacker can place a variant sequence inside the message body followed by a fresh `MAIL FROM` / `RCPT TO` / `DATA` block. The inbound server splits one SMTP transaction into two: the carrier (which passes authentication because it is sent through the legitimate, authenticated outbound relay) and the smuggled message whose From is fully attacker-chosen. Because alignment checks look at the carrier envelope, the spoofed message is delivered with passing auth and no warning.

## Attack phases
Exploitation (spoofing/phishing); enables high-credibility phishing from trusted domains.

## Prerequisites
- An outbound SMTP service the attacker can send through (often an account on a provider whose server tolerates or emits a non-standard end-of-data variant).
- A target inbound server that accepts a different end-of-data interpretation.
- The spoofed sender domain need not be controlled; the goal is to ride the carrier's passing SPF/DKIM/DMARC.

## Methodology
1. Identify outbound and inbound mail stacks (banner, provider, MX records).
2. Test which end-of-data variants each side accepts (`<LF>.<LF>`, `<CR>.<CR>`, etc.).
3. Craft a carrier email; inside its DATA, place the smuggling sequence then a second SMTP conversation (`MAIL FROM:<spoofed@trusted>`, `RCPT TO:<victim>`, `DATA`, spoofed headers/body, `.`).
4. Send via the authenticated outbound relay so the carrier passes SPF/DKIM/DMARC.
5. Confirm the inbound server delivers the smuggled message to the victim with the spoofed From and passing auth results.

## Key payloads / examples
Smuggled second message inside the DATA of a carrier (the inner non-standard end-of-data sequence is the key):
```
MAIL FROM:<attacker@attacker.tld>
RCPT TO:<victim@target.tld>
DATA
From: attacker carrier
<body line>
<LF>.<LF>           <- inbound treats this as end-of-data, starts a NEW transaction
MAIL FROM:<ceo@trusted-bank.com>
RCPT TO:<victim@target.tld>
DATA
From: CEO <ceo@trusted-bank.com>
Subject: Wire transfer
Spoofed body. SPF/DKIM/DMARC pass via the carrier envelope.
.
```

## Bypasses and variants
- Variant sequences to try: `<LF>.<LF>`, `<CR>.<CR>`, `<LF>.<CR><LF>`, `<CR><LF>.<CR>`; pick the pair where outbound and inbound disagree.
- Affected real stacks (2023 disclosure): Microsoft Exchange Online, GMX, and Cisco Secure Email (the Cisco default configuration remained exploitable after disclosure).
- Conceptually a sibling of HTTP request smuggling; see [[http-request-smuggling]].

## Detection and defence
- Enforce strict RFC 5321 end-of-data handling; reject bare `<LF>` and bare `<CR>` line endings and non-standard dot termination.
- Normalise line endings at the boundary; do not accept `<LF>.<LF>` as end-of-data.
- Mail providers: patch to versions that reject ambiguous sequences (Microsoft and GMX patched).
- Monitor for messages whose internal structure contains extra SMTP verbs.

## Tools
Reproducible with a raw SMTP client (`swaks`, netcat). SEC Consult published a testing methodology. See [[http-request-smuggling]] for the analogous HTTP class.

## Sources
- SEC Consult / Timo Longin, "SMTP Smuggling - Spoofing E-Mails Worldwide" (slug: secconsult-smtp-smuggling).
- SecurityWeek, "SMTP Smuggling Allows Spoofed Emails to Bypass Authentication Protocols" (slug: securityweek-smtp-smuggling).
