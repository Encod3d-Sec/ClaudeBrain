---
name: screenshot
description: Capture web-page / PoC screenshots into the engagement evidence (targets/<eng>/poc/) and embed them in walkthrough.md. Live pages + authenticated/exploited states (post-login dashboard, the flag page, an SSTI/cmdi render). Runs chromium on the Kali tooling host (VPN path to targets); hands off to the evidence skill for redaction before a real report. Use when building PoC evidence or asked to "take a screenshot / capture the PoC".
---

# Screenshot: visual PoC capture

Turn the text walkthrough into evidence. Capture runs on the **Kali tooling host** (it has the VPN
route to in-scope targets); the PNG is then pulled into the vault under `targets/<eng>/poc/`. Driver:
`scripts/shot.py` (chromium headless). For redaction-before-report use `Skill(evidence)`.

**Two evidence dirs.** `poc/` = the curated story you choose to show (login, the exploited state, the
flag) - everything this skill captures by hand lands here. `recon/` = the auto-captured firehose of
scan-tool cards (nmap/ffuf/nuclei/nxc/linpeas/pspy) the Stop-hook drain fills on its own; pull the ones
worth keeping into the `## Evidence` gallery, ignore the rest.

## Scope check
Only screenshot **in-scope** hosts (read `targets/<eng>/scope.md`). On `passive_only` RoE a screenshot
is fine (it's a GET you already make). Never screenshot a host you would not curl.

## What to capture: EVERY breakthrough, as it happens (with retries)
Screenshot the moment each step LANDS, not at the end - the box may expire. A breakthrough = anything
you'd put in the report: the **entry page**, a **leaked secret / useful source** (deobfuscated JS, a
config, an `app.log`), the **cipher / decrypt response**, the **vuln firing**, the **authed/exploited
state**, the **flag**. Tell the arc (Entry -> Trigger -> Impact) AND capture the intermediate proofs
(the leak, the crypto response) - those are exactly what a reviewer disbelieves without a picture.
- **Always show the URL.** Every web/source capture must carry its address bar so the image is
  self-identifying - which page/path it is (`https://T/folder/folder/log.md`), not an anonymous blob.
  Live `<url>` mode adds it automatically; for `--html`/`--term` of a fetched resource pass
  `--url-bar "<full URL>"`.
- **Retry (box is up).** Renders fail transiently (nav timeout, cold chromium). Retry 2-3x and confirm
  the PNG is non-empty (`[ -s out.png ]`) before moving on; while the box is up, go back and re-capture
  anything you missed rather than shipping evidence with gaps.
Name `NN-slug.png` (NN = step order) so the evidence reads top-to-bottom.

## Fastest path: `capture.sh ev` (one call, live - USE THIS by default)
Batching captures at the end of a box is the failure mode: you lose transient state AND the live
situational awareness that helps pick the next move when stuck. The `ev` mode of `scripts/capture.sh`
collapses the whole capture (render a card showing **command + request URL**, pull the PNG into `poc/`,
print the md ref) into ONE call, so live capture has no friction. `cmd` and `url` are REQUIRED args - no
anonymous card.
```bash
# 1) tee the step's output on the VM as you run it (safe for stateful exploits - no re-run needed):
bash /root/vm.sh 'python3 /tmp/exploit.py 2>&1 | tee /tmp/poc/flag3.log'
# 2) card it the MOMENT it lands:
scripts/capture.sh ev <eng> flag3-contract "POST http://T:8545 eth_sendTransaction" "reset()+transferDeposit()"
#   args: <eng> <slug> <request-url> <cmd-label> [logfile=/tmp/poc/<slug>.log]
#   -> saves targets/<eng>/poc/NN-flag3-contract.png (NN auto-numbered), prints the ![]() ref
```
The card shows `$ <cmd-label>` in the title bar AND `<request-url>` in a browser address bar (both
required) so every image says what was run and where. Use the manual `shot.py` calls below only for the
modes `capture.sh ev` does not wrap (a live web page, a `--tmux` scan tab, a GUI `--window`/`--screen`).

## Request/response leads: automatic capture + `capture.sh req`
The highest-value CTF/pentest evidence is the **real curl request and response** for a lead (creds, a
flag, a leaked source) - presentable as full-file PoC. Two live mechanisms, so a lead is never missed:

**Automatic (the net, no action needed):** when a `curl`/`wget` to an in-scope target returns a lead
signal (credential/key/flag/leaked source/dir-listing), the `recon-capture.py` hook auto-stages a
request+response card to `targets/<eng>/poc/leads/` and the Stop-hook drain renders it. This is why
leads get captured even mid-exploit. Curate the good ones into the walkthrough; if a plain `curl` (no
`-i/-v`) fired it, the hook nudges you to re-capture the full headers with `capture.sh req`.

**Deliberate + full fidelity (`capture.sh req`):** for a request you want as a clean PoC (request line +
headers + body, response status + headers + body), run it through the `req` mode - it runs `curl -sS -iv`,
colors the request(`>`)/response(`<`) Burp-style, and pulls the PNG into `poc/`:
```bash
scripts/capture.sh req <eng> <slug> -- -sk -X POST https://T:5000/login --data @/tmp/body.txt
```
For a **crypto-forged** request (envelope/signature), give the exploit script a `--curl` mode: it writes
the forged body to a file and prints the `capture.sh req` args, so the PoC is a reproducible curl, not
"run my python". Never settle for a script-summary card (`POST https://T/login` + python output) when the
real curl request/response is the artifact a client / writeup needs.

## Page evidence: also automatic now (`poc/pages`)
An in-scope HTML GET is covered by the same net: `recon-capture.py` stages the page and the loop-driver
Stop-drain renders it as ONE COMBINED card, the chromium browser render of the page stacked on TOP of
the curl request/response card underneath, landing in `targets/<eng>/poc/pages/*.png`. No manual
screenshot step is needed for a normal in-scope page GET (same pattern as the `poc/leads/` and `recon/`
auto-capture above). This skill's DELIBERATE capture is for what that auto path does NOT cover:
authenticated/exploited states (post-login dashboard, the vuln firing, the flag page) and the
narrative `capture.sh tmux`/`--tmux` real-session cards, not a plain in-scope page GET.

## Real tmux-session cards: `capture.sh tmux`
When the evidence should look like an ACTUAL Kali terminal session (real commands + real output, the way
recon scans are captured), run the proof in a real tmux pane and screenshot the pane:
`scripts/capture.sh tmux <eng> <slug> <script.sh>` runs the script in a wide tmux pane, waits for its
`echo POC-DONE`, `--tmux`-captures the pane (FULL scrollback), colors it, and pulls the PNG into `poc/`.
Write the script to `echo "# comment"` and `echo "$ <command>"` then run the real `curl -i`/exploit
command. The card colors **comment (green) / command (cyan) / response (default)** so the three are
visually distinct (`shot.py --reqresp`, works on `--term` and `--tmux`).

**NEVER truncate or abbreviate evidence.** Show the FULL command, FULL request, FULL response - no `...`,
no `<result=...>` placeholder, no eliding a base64 blob or a long body. A reviewer must verify/reproduce
from the image ALONE. The tooling enforces this (`capture.sh tmux` captures full pane scrollback via
`--history` and never caps rendered lines); keep the same discipline in the script content - paste the
real value, never summarize it.

## Capture (run on Kali via vm.sh)
Push the script once, then shoot. `T` = target host, `PORT` = web port, `<eng>` = engagement dir.
```bash
# 0) push shot.py to Kali (once per session). vm.sh does NOT forward local stdin, so base64 the
#    file INTO the command (a `... | vm.sh 'cat > file'` pipe silently writes an EMPTY file):
B64=$(base64 -w0 scripts/shot.py); bash /root/vm.sh "mkdir -p /tmp/poc; echo $B64 | base64 -d > /tmp/shot.py"

# 1) LIVE page (unauth / GET-able): the URL address bar is added AUTOMATICALLY
bash /root/vm.sh 'python3 /tmp/shot.py http://T:PORT/internal --step 1 --slug login --dir /tmp/poc --caption "NOC login"'

# 2) AUTHED / exploited state: curl WITH the session, save HTML, render it. Pass --url-bar so the
#    image shows WHICH URL produced it (the authed path, or the exact exploit request); --base loads
#    /static from the target; the cookie stays in curl, never in the browser.
bash /root/vm.sh 'curl -s -b "session=VAL" http://T:PORT/internal/dashboard > /tmp/d.html;
  python3 /tmp/shot.py --html /tmp/d.html --base http://T:PORT --url-bar "http://T:PORT/internal/dashboard" --step 3 --slug dashboard --dir /tmp/poc --caption "Dashboard via SQLi"'
```
shot.py prints `saved <path>` + a ready `md: ![caption](poc/NN-slug.png)` line - keep that line.

## Terminal-tool + source/log capture (--term)
Render console output OR a fetched source/log/config file as a clean colored card (ANSI converted,
never shown raw). The fancy 2-line shell prompt is **auto-stripped** so a tmux grab is not a fused
`rootnmap -p-` mess (`--raw` keeps prompts if you need them). For a fetched web resource, add
`--url-bar` so the card shows its URL - a leaked source file is evidence only if you can see where it lives.
```bash
bash /root/vm.sh 'nmap -sV T | tee /tmp/o.txt;
  python3 /tmp/shot.py --term /tmp/o.txt --cmd "nmap -sV T" --step 1 --slug nmap --dir /tmp/poc'
# a leaked source / log / config, WITH its URL in the address bar:
bash /root/vm.sh 'curl -s http://T/logs/app.log > /tmp/l.txt;
  python3 /tmp/shot.py --term /tmp/l.txt --url-bar http://T/logs/app.log --cmd "GET /logs/app.log" -o /tmp/poc/app-log.png'
```
`--maxlines` (default 120) caps long output (linpeas); the card auto-sizes to wrapped rows so a long
obfuscated-JS line does not crop the reveal. Then pull the PNG into `poc/` like the web shots above.

**Auto catch-all:** actually INVOKING nmap/ffuf/nuclei/nxc/linpeas/pspy at command position (a poll
loop / `grep` / `cd` that merely *mentions* the name does NOT fire) auto-stages its output
(`recon-capture.py`); the Stop-hook drain renders those clean (prompt-stripped) to `recon/` and appends
a row to `recon/.pending/manifest.md`. Pull the rows worth showing into the `## Evidence` gallery.
Deliberate story shots (the box's arc) still use the calls above and land in `poc/`. Scans you run
detached in a tmux tab (`vm-scan.sh`) don't return output to the response, so capture those live with
`--tmux <eng>:<tab>` once the pane has output.

## Run scans in tmux + capture them (nmap/ffuf/nuclei live)
Run each scan in a named tmux tab on the VM (root, persistent - survives the vm.sh call),
one tab per target; multi-web targets get one tab per endpoint:
```bash
bash scripts/vm-scan.sh <eng> T 'nmap -sV -Pn T'                 # tab: T
bash scripts/vm-scan.sh <eng> T-web-192.0.2.10 'ffuf -u http://192.0.2.10/FUZZ -w wl'
```
Tab name correlates to the target; dots/colons/spaces become `-` (tmux target syntax).
Screenshot a live/finished tab as a clean colored card (no display needed):
```bash
bash /root/vm.sh 'python3 /tmp/shot.py --tmux <eng>:T --step 2 --slug nmap --dir /tmp/poc'
```
Target the tab by the `@NN` window id or the sanitized name (dots/colons became `-`) that `vm-scan.sh` printed, not the raw dotted target.
then pull the PNG into `poc/` as usual.

## GUI / desktop capture (scrot)
For real GUI apps with no text stream (Burp, Wireshark, a browser rendering an exploit)
or the whole desktop:
```bash
bash /root/vm.sh 'python3 /tmp/shot.py --window "Burp Suite" --step 3 --slug burp --dir /tmp/poc'
bash /root/vm.sh 'python3 /tmp/shot.py --screen --step 4 --slug desktop --dir /tmp/poc'
```
shot.py wakes + unlocks the seat session and grabs as the desktop user (root-over-SSH has
no X authority, so a bare `scrot` fails with "Can't open X display :0"). `--window` grabs
the named app (even behind a lock); it falls back to full screen if the name is not found.
Use `--term` for tool STDOUT text, `--tmux` for a live tmux scan tab, `--screen`/`--window`
for GUI windows.

## Pull into the vault (Kali -> WSL, base64 over the channel)
The PNG is born on Kali; the vault is on WSL. Transfer each:
```bash
mkdir -p targets/<eng>/poc
bash /root/vm.sh 'base64 -w0 /tmp/poc/03-dashboard-after-sqli.png' | base64 -d > targets/<eng>/poc/03-dashboard-after-sqli.png
```

## Embed in the walkthrough
- Drop the printed `![caption](poc/NN-slug.png)` ref **inline at the matching step** in `walkthrough.md`.
- Maintain a `## Evidence` appendix (one row per shot) so the gallery is browsable:
```markdown
## Evidence
| shot | caption |
|------|---------|
| ![](poc/01-login.png) | NOC login (/internal) |
| ![](poc/03-dashboard-after-sqli.png) | Dashboard reached via SQLi bypass |
```
Images live only under `targets/<eng>/` (gitignored) - never embed images in `wiki/` (image-free rule).

## Lesson: capture live, not at the end (THM TriCipher)
The whole box was solved (3 flags: supply-chain cred intercept -> OTP crypto crack -> smart-contract
`reset()`), and only THEN screenshotted by re-running the commands. Two real costs: (1) no mid-engagement
evidence to reason from while stuck - the long dead-end hunting the login username would have been easier
to unstick with the intercepted-creds card and the cipher-response card already in hand; (2) re-running is
unsafe for stateful steps (a spent padding-oracle or a contract `transferDeposit()` that zeroes a balance
cannot be re-fired for a clean card). Fix: `capture.sh ev` after EACH landing step, not at the end. Also
banked into `shot.py`: `--term` cards budget generous bottom headroom so the last line (usually the
flag/cred) never clips, and every card carries BOTH the command and the request URL.

**Preserve the exploit code too, not just the screenshot.** When you write an exploit script (a
payload HTML, an escape/forge script, a webshell) or read a target's source, copy it into
`targets/<eng>/poc/scripts/` alongside its card, so the reviewer has the code and the state together,
the thm_tricipher standard.

## Redaction (real engagements only)
Before a client report, run `Skill(evidence)`: black-bar session cookies / PII, strip
metadata. The authed-via-curl-to-HTML flow already keeps the session token out of the image (it's in
curl, not the URL bar). CTF/lab: skip redaction.

## Output
Report: shots saved (paths under `poc/`), the `![]()` refs added to `walkthrough.md`, any blocker
(nav timeout -> raise `--wait`; missing styles -> set `--base`).
