---
name: screenshot-burp
description: Capture a Burp Suite Repeater request/response as a PoC image (targets/<eng>/poc/) by driving the Burp MCP + the Kali GUI. Replays a request in a Repeater tab, sends it, and grabs the request+response panes - a Burp-native PoC (client report / CTF writeup). Use when you want the evidence to come from Burp rather than a curl/terminal card, or whenever you drive a target through Burp and need the images. Pairs with hunt-burp.
---

# Screenshot: Burp Repeater request/response PoC

Turn a Burp Repeater exchange into a report-ready **request + response image**. This is the Burp-native
counterpart to `Skill(screenshot)` (curl/terminal cards): when you drive a target through Burp, capture
the proof FROM Burp. Prereqs are the same as `Skill(hunt-burp)` (Burp running + the MCP Server BApp, SSE
on `127.0.0.1:9876`; verify with `bash /root/vm.sh 'python3 ~/burp-mcp-cli.py list'`).

## One command (use this)
```bash
scripts/capture.sh burp <eng> <slug> <host> <port> <https:true|false> <method> <path> [bodyfile] [tabname]
# POST with a body file (forged/complex bodies -> write to a file, avoids shell quoting):
scripts/capture.sh burp thm_x flag1 10.1.1.1 5000 true  POST /login /tmp/login_body.txt "ECorp login"
# simple GET:
scripts/capture.sh burp thm_x flag3 10.1.1.1 3000 false GET  /challenge/solve
```
It: (1) `create_repeater_tab` via the MCP with the raw request, (2) activates Burp on the seat display,
focuses the request editor, sends with **Ctrl+Space** (Burp's Repeater Send hotkey), (3) `import`-grabs
the window and pulls `targets/<eng>/poc/NN-<slug>.png`, printing the `![]()` ref. Drop that ref into
`walkthrough.md` so the image actually renders in Obsidian (an un-referenced PNG in `poc/` is invisible
in the notes - only reachable by opening the folder).

**Crypto-forged / signed requests:** give the exploit script a `--curl`-style mode that writes the exact
body to a file (e.g. `/tmp/login_body.txt`), then pass it as `bodyfile`. The Repeater tab then holds the
real forged request, so the PoC is Burp-native and reproducible.

## Gotchas baked into `capture.sh burp` (the burp mode) (why hand-rolling this failed the first time)
- **Grab as the SEAT user, not root.** Burp may be root-owned but it DRAWS on the desktop user's X
  session (the desktop login on `:0`). `who` -> the line with a `(:N)` display gives the user + display; use their
  `~/.Xauthority`. A root-over-SSH grab has no X display.
- **Send = Ctrl+Space (KEYBOARD only).** On the Kali WM, synthetic `xdotool` MOUSE clicks do NOT register
  in Burp (Java Swing) - button/tab clicks are silent no-ops - but KEYBOARD events DO (Ctrl+Shift+R switches
  tabs, Ctrl+Space sends). the burp mode's `mousemove;click` before Ctrl+Space is a harmless no-op; the send
  works because `create_repeater_tab` leaves the request editor focused. Corollary: **you cannot click the
  Send button, a top tab, or a BApp tab by pixel** - drive everything by keyboard, and anything with no
  hotkey (e.g. the BApp `MCP` tab) is NOT automatable - it needs a human mouse action.
- **Window offset:** `getwindowgeometry` -> the client area sits at screen (0, ~35); the `import -window`
  grab starts at the client top, so screen_y = image_y + 35 (only matters if you ever DO need a click on a
  WM that accepts synthetic clicks; this one does not).
- **Write the grab to a WORLD-WRITABLE path** (`/tmp/capture_burp_*.png`), never a root-owned `-o` dir: the
  sudo-as-seat-user `import` can't write into `/tmp/poc` if root created it (silent EACCES = "no PNG").
- **MCP SSE wedges on MULTIPLE SESSIONS - so do ALL calls in ONE session.** The root cause of the wedge
  is opening a NEW SSE session per call (which `burp-mcp-cli.py call ...` does - one process = one session):
  the first session works, then the server stops serving new ones (hands out an endpoint but never answers
  the POST). **The right model, and the answer to "drive Burp via MCP, then just screenshot":** open ONE SSE
  session and issue EVERY `create_repeater_tab` you need in it (stage all the request tabs at once), THEN do
  the GUI part - which is KEYBOARD-ONLY and reliable: for each tab, `Ctrl+Shift+R` (Repeater) + `Ctrl+Tab`
  to the tab + `Ctrl+Space` (send) + `import`-grab. No mouse anywhere. A single-session multi-tab client is
  in scratch `burp_multi.py`; fold it into the burp mode as a batch mode. Once a server is ALREADY wedged
  (from earlier per-call sessions) even a one-session client times out -> it needs a BApp restart to reset.
- **Legacy note (single-call CLI).** `create_repeater_tab` / `send_http1_request` via the per-call CLI work
  on the FIRST call of the Burp session, then wedge. `capture.sh burp` (single-call CLI) surfaces this; the
  fix is to **restart the MCP Server BApp** (Burp's `MCP` tab -> toggle the server off/on) - but that is a
  mouse action the model CANNOT automate here (synthetic clicks don't register), so it is a **HUMAN step**:
  ask the operator to toggle it, then run `capture.sh burp` again. If waiting on a human isn't acceptable,
  route the request through Burp's proxy (`curl -x 127.0.0.1:8080 ...`) so it lands in Proxy history and
  grab that instead - no MCP needed. So: **`capture.sh burp` gets ONE clean run per MCP-server session**;
  batch the requests you need, or expect a human toggle between them. (Bank recurring quirks in [[burp-mcp]].)

## Manual fallback (what the script automates)
```bash
# 1) stage the request as a Repeater tab (root, via MCP)
bash /root/vm.sh 'python3 ~/burp-mcp-cli.py call create_repeater_tab "{\"content\":\"GET /x HTTP/1.1\r\nHost: T:80\r\nConnection: close\r\n\r\n\",\"targetHostname\":\"T\",\"targetPort\":80,\"usesHttps\":false}"'
# 2) send + grab as the seat user (detect the desktop user + display from `who`)
bash /root/vm.sh 'U=$(who | awk "/\(:[0-9]/{print \$1;exit}"); D=$(who|grep -oE "\(:[0-9]+"|head -1|tr -d "(")
  sudo -u "$U" env DISPLAY="$D" XAUTHORITY=/home/$U/.Xauthority bash -c "
  WID=\$(xdotool search --name \"Burp Suite Professional\" | head -1)
  xdotool windowactivate --sync \$WID; xdotool mousemove 500 400 click 1; sleep .4
  xdotool key ctrl+space; sleep 4; import -window \$WID /tmp/burp.png"'
# 3) pull it
bash /root/vm.sh 'base64 -w0 /tmp/burp.png' | base64 -d > targets/<eng>/poc/NN-slug.png
```

## Redaction / boundary
Same as `Skill(screenshot)`: images live only under `targets/<eng>/` (gitignored); run `Skill(evidence)`
before a client report (Burp responses can carry cookies/PII). Never embed in `wiki/`.

## Output
Report: the `poc/NN-slug.png` saved + the `![]()` ref added to `walkthrough.md`; note if the MCP wedged
(and whether you restarted it or fell back to the proxy).
