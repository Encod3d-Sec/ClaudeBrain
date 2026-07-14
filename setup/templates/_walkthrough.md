---
title: "Walkthrough - <ENGAGEMENT>"
type: engagement-walkthrough
tags: [engagement, walkthrough, reproduction]
date_created: <DATE>
date_updated: <DATE>
sources: []
---

# Walkthrough - <ENGAGEMENT>

Full **reproducible** escalation path: ordered, copy-pasteable steps from zero to the objective
(root / domain admin / target flag). Unlike `log.md` (terse, append-only audit) this is the
**rebuild-from-scratch recipe**: every step carries the EXACT command + the result that confirms
it, so the box can be re-owned (or a report PoC rebuilt) without re-deriving anything. The
engagement dir is git-ignored, keep real creds/flags here.

**TL;DR chain:** `<entrypoint>` -> `<foothold / user>` -> `<privesc>` -> `<root / objective>`

---

## 0. Access / connectivity
<!-- How you get on the wire: VPN iface + route, jump/attack box, any starting creds.
     Record gotchas that cost time (wrong VPN region, route binding, unreachable-from-host),
     so the next run skips them. -->
- target:
- reach:

## 1. Recon
<!-- The scans + ONLY the findings that mattered: open ports, services + versions, key endpoints. -->
```
# cmd
```
- result:

## 2. Foothold  (-> user)
<!-- The vuln, exact exploit steps, how the first shell/creds were obtained, the user flag.
     Paste the working payload, not a description of it. -->
```
# cmd / payload
```
- result:
- **user flag:**

## 3. Privilege escalation  (-> root)
<!-- The enumeration that found the vector (pspy / linpeas / manual + what it showed), then the
     exact escalation steps. -->
```
# cmd / payload
```
- result:
- **root flag:**

---

## Flags
| scope | value | path |
|-------|-------|------|
| user  |       |      |
| root  |       |      |

## Evidence
<!-- Visual PoC. Capture with Skill(screenshot) -> scripts/shot.py (chromium on Kali); images land
     in this engagement's poc/ dir (gitignored; images are fine here, NOT in wiki/). Inline the refs
     at the matching step above; list them here as a gallery. -->
| shot | caption |
|------|---------|
<!-- | ![](poc/01-login.png) | NOC login page | -->

## One-shot reproduction (optional)
<!-- A single script/sequence that re-owns the target from clean, for verification or a report
     appendix. Point at any scripts kept in this engagement's poc/ dir. -->

## Rabbit holes (skip on redo)
<!-- Dead-ends that wasted time. Listing them makes the next run / re-test faster. Mirror the
     one-liners in Deadends.md. -->
-
