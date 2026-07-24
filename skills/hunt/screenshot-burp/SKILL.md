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
- **Send = Ctrl+Space (KEYBOARD only); mouse is dead.** Java Swing IGNORES synthetic `xdotool` MOUSE clicks
  (button/tab/pixel clicks are silent no-ops), but KEYBOARD events land once the window is activated
  (`windowactivate --sync`): `Ctrl+Shift+R` (focus Repeater), `Ctrl+=` (next sub-tab), `Ctrl+Space` (Send).
  Drive everything by keyboard; anything with no hotkey (e.g. the BApp `MCP` tab) needs a human mouse action.
- **Window offset:** `getwindowgeometry` -> the client area sits at screen (0, ~35); the `import -window`
  grab starts at the client top, so screen_y = image_y + 35 (only matters if you ever DO need a click on a
  WM that accepts synthetic clicks; this one does not).
- **Write the grab to a WORLD-WRITABLE path** (`/tmp/capture_burp_*.png`), never a root-owned `-o` dir: the
  sudo-as-seat-user `import` can't write into `/tmp/poc` if root created it (silent EACCES = "no PNG").
- **The "SSE wedge" was a MISDIAGNOSIS (corrected 2026-07-24).** The only MCP call that ever hung is
  `send_http1_request`, and that is the extension's **target-approval gate** (a non-approved target raises a
  GUI approval prompt a headless seat cannot answer -> 15s timeout), NOT a per-session wedge. `create_repeater_tab`,
  `get_active_editor_contents`, `url_encode`, `set_proxy_intercept_state` all run fine across many back-to-back
  per-call sessions. `capture.sh burp` never calls `send_http1_request` (it Sends in the GUI via `Ctrl+Space`,
  human-equivalent, which bypasses the approval gate), so it is unaffected. If `create_repeater_tab` itself
  fails, the server is down/unreachable -> check `scripts/burp-transport.sh` (see [[burp-mcp]]).

## Selecting the finding's tab (SOLVED 2026-07-24, Burp 2026.3.x, verified end-to-end)
`create_repeater_tab` appends the tab RIGHTMOST but does NOT focus it, so a naive grab caught whatever tab was
last active (the old stale-tab PoCs). `capture.sh burp` now SELECTS the intended tab deterministically and
VERIFIES it before Send/grab, so a wrong-tab PoC is impossible. The sequence (all baked into the burp mode):
1. **Unlock + wake the seat FIRST.** A Kali screen LOCK (seat0) routes synthetic input to the locker, so
   `getmouselocation` over Burp reports `window:0` and NO key/click lands -- burpshot then silently caught the
   wrong tab. `loginctl unlock-session <seat0-sid>` (root) dismisses the lock; `xset dpms force on` + `xset s off`
   (seat user) wake the display. Without this a locked/idle VM fails the precheck. (`shot.py` already did this;
   `capture.sh burp` now does too.)
2. **Interactivity precheck** = mouse `getmouselocation` over Burp returns the Burp WID (not `window:0`). This is
   the RELIABLE check; `wmctrl -lG` is NOT -- it reports "no managed windows" on this no-WM seat even when input
   lands, a false negative.
3. **SELECT by keyboard + oracle.** `Ctrl+=` (`go_to_next_tab`, it WRAPS) steps sub-tabs; after each step read
   `get_active_editor_contents` and stop when it shows the created request's `METHOD PATH` line (cap 16, fail loud
   if never confirmed). The old "Ctrl+= does not move the tab" finding was from the LOCKED-seat era when no input
   landed at all -- once unlocked, `Ctrl+=` selects the tab AND focuses its editor, which the oracle reads. (Marker
   = the request line; a distinctive path keeps it unambiguous -- identical request-lines across tabs match the
   first found.)
4. **Send + grab.** `Ctrl+Space` sends the now-confirmed tab; `import -window $WID` grabs it. The run prints
   `GRAB_OK ... (verified tab: <marker>)`; a `GRAB_FAIL` tells you why (locked seat the unlock did not clear, or
   MCP down -> `burp-transport.sh`).
CAPTURE was never the problem: `import -window` works headless; **flameshot FAILS on this seat** ("Unable to
capture screen" -- no DBus/portal in the minimal X), so for a tighter crop use `import -window $WID -crop
WxH+X+Y +repage` or `maim`/`scrot -a` (pure X11), never flameshot here.

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
