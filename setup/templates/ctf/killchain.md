---
title: "Kill-Chain Board - <ENGAGEMENT>"
type: engagement-killchain
engagement_type: ctf
tags: [engagement, killchain, board]
date_created: <DATE>
date_updated: <DATE>
sources: []
---
# Kill-Chain Board - <ENGAGEMENT>

Status: `[ ]` todo | `[~]` doing | `[x]` done | `[-]` n/a | `[!]` deadend (-> Deadends.md)
GATE 1 (wiki): no hand-rolled exploit until its Weaponize wiki item is `[x]`.
GATE 2 (poc):  no exploit step goes `[~]`->`[x]` without a poc/ image.
GATE 3 (loop): a vector exhausted -> mark `[!]`, one Deadends line, move to the next open item. Never re-run `[!]`.

## 1. Recon  ([[recon]] · [[service-enumeration]] · [[network-services]])
- [ ] rustscan all ports                 -> [[rustscan]]
- [ ] nmap -sCV on open ports            -> [[nmap]]
- [ ] service enum per port              -> [[service-enumeration]]
- [ ] DNS enum (dig any / axfr)          -> [[recon]]
- [ ] wiki-query EACH fingerprinted tech/version   <-- GATE 1 source
  (web, per http port:)
- [ ] whatweb + httpx + screenshot       -> [[whatweb]] [[httpx]] + Skill(screenshot)
- [ ] ffuf/feroxbuster dirs + vhosts     -> [[ffuf]] [[feroxbuster]] [[gobuster]] [[wordlists]]
- [ ] arjun param mining                 -> [[arjun]]
- [ ] nuclei                             -> [[nuclei]] [[nuclei-arsenal]]
- [ ] nikto ; wpscan (if WordPress)      -> [[nikto]] [[wpscan]]
- [ ] katana/gau crawl -> review links, `<script>`, .js  -> [[katana]] [[gau]] [[javascript-source-map-exploitation]]
- [ ] trufflehog / .git exposure         -> [[trufflehog]] [[git-exposure]]
  (recon, multi-host / subdomains:)
- [ ] subfinder + dnsx + gowitness       -> [[subfinder]] [[dnsx]] [[gowitness]]
  (osint, if in scope -- ask:)
- [ ] OSINT sweep                        -> [[osint-moc]] [[recon-dorks]] [[secret-hunting]]

## 2. Weaponize  ([[cve-arsenal]] · [[attack-chains]] · [[oob-callbacks]])
- [ ] searchsploit + wiki CVE lookup per version -> [[cve-arsenal]] [[metasploit]]
- [ ] pick payload set from wiki/payloads/       -> Skill(arsenal)
- [ ] stage exploit into poc/scripts/

## 3. Deliver  ([[burp-mcp]] · [[reverse-shells]])
- [ ] deliver payload (burp repeater / curl / upload) -> [[burp-mcp]] [[file-upload]]
- [ ] get a shell (reverse / bind) + stable PTY       -> [[reverse-shells]]
- [ ] cred reuse tried before new creds               -> loot.md [[default-credentials]]
- [ ] fuzz params / request items                     -> [[ffuf]] [[arjun]]

## 4. Exploit

### 4a. Foothold  (subsumes coverage.md: asset x class x status)
| target | vuln class | wiki | payload/tool | status | poc |
|--------|-----------|------|--------------|--------|-----|

cred attacks:  sqlmap / hydra / medusa / john / hashcat
  -> [[sqlmap]] [[hydra]] [[medusa]] [[john]] [[hashcat]] [[password-attacks]] [[wordlists]] [[default-credentials]]
route by class: Skill(arsenal) -> Skill(`hunt-<class>`)

### 4b. Post-Ex / Privesc  ([[linux-privesc]] · [[privesc-exploit-arsenal]])
- [ ] pspy (cron/timers/bg jobs)     -> [[pspy]]
- [ ] linpeas / winpeas              -> [[linpeas]] [[linux-enumeration]] [[windows-enumeration]]
- [ ] sudo -l / SUID / caps / cron / timers / groups  -> [[linux-privesc]] [[windows-privesc]]
- [ ] docker / lxd / container check -> [[docker-attacks]] [[linux-container-escape]]
- [ ] internal services / pivot      -> [[pivoting]] [[chisel]] [[ligolo-ng]] [[file-transfer]]
- [ ] persistence (if required)      -> [[linux-persistence]] [[windows-persistence]]

### 4c. Objective
- [ ] user flag / initial objective
- [ ] root flag / DA / target impact
