#!/usr/bin/env python3
"""shot.py - capture a web page / PoC state to PNG. Runs on the Kali tooling host
(it has the VPN path to in-scope targets). Engine: chromium --headless (works as
root with --no-sandbox; playwright's driver is broken on Kali and cutycapt's zygote
refuses root, so chromium is the reliable path).

Modes:
  live   : shot.py <url> -o out.png                         # unauth / publicly GET-able page
  authed : curl -s -b 'session=..' <url> > p.html
           shot.py --html p.html --base http://T:port -o out.png
           # render the authed response; --base rewrites root-relative asset URLs so CSS/JS load
           # from the target (chromium is on Kali = VPN access). The cookie stays in curl, never
           # in the browser -> faithful to the server's authed response, no token-in-image leak.

Naming : -o <path>   OR   --step N --slug S [--dir D]  ->  D/NN-slug.png
Prints the saved path + a ready  ![caption](poc/NN-slug.png)  line for the walkthrough.
"""
import argparse
import html as _html
import os
import re
import shutil
import subprocess
import sys
import tempfile


def chromium_bin():
    for b in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(b):
            return b
    return "chromium"


def slug_outname(step, slug):
    """(3, 'Dashboard After SQLi') -> '03-dashboard-after-sqli.png'."""
    s = re.sub(r"[^a-z0-9]+", "-", str(slug).lower()).strip("-")[:40] or "shot"
    return "%02d-%s.png" % (int(step), s)


def md_ref(outname, caption=""):
    return "![%s](poc/%s)" % (caption or outname.rsplit(".", 1)[0], outname)


# xterm-ish 16-color foreground palette (normal 30-37, bright 90-97).
_ANSI_FG = {30: "#3b4048", 31: "#e05561", 32: "#8cc265", 33: "#d18f52",
            34: "#4aa5f0", 35: "#c162de", 36: "#42b3c2", 37: "#d7dae0",
            90: "#57606f", 91: "#ff616e", 92: "#a5e075", 93: "#f0a45d",
            94: "#4dc4ff", 95: "#de73ff", 96: "#4cd1e0", 97: "#ffffff"}
_ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_to_html(text):
    """Convert SGR-colored terminal text to HTML span runs. Handles reset(0),
    bold(1), and 16-color foreground; other SGR codes are dropped. The text
    payload is HTML-escaped so tool output can't inject markup. Each SGR fully
    replaces the prior style (no accumulation) -- sufficient for tool output
    that emits a full SGR per token then resets."""
    out, pos, open_span = [], 0, False

    def close():
        nonlocal open_span
        if open_span:
            out.append("</span>")
            open_span = False

    for m in _ANSI_RE.finditer(text):
        out.append(_html.escape(text[pos:m.start()]))
        pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c != ""] or [0]
        style = []
        for c in codes:
            if c == 1:
                style.append("font-weight:bold")
            elif c in _ANSI_FG:
                style.append("color:" + _ANSI_FG[c])
        close()
        if style:
            out.append('<span style="%s">' % ";".join(style))
            open_span = True
    out.append(_html.escape(text[pos:]))
    close()
    return "".join(out)


_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")
# any ESC-introduced escape/control sequence: OSC (title-set etc, terminated by BEL or
# ST), CSI (cursor move / erase-line / private-mode -- any final byte, SGR included),
# 2-char charset-select, misc single-char escapes, or a lone/unterminated ESC. SGR is
# matched here too (so the whole token is consumed atomically) -- _keep_sgr below decides
# whether to keep or drop each match.
_ESCAPE_TOKEN_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"    # OSC ... BEL or ST
    r"|\x1b\[[0-9;?]*[ -/]*[@-~]"           # CSI ... final byte
    r"|\x1b[()#][A-Za-z0-9]"                # charset select (2-char)
    r"|\x1b[=><NOPX^_\\]"                   # misc single-char escapes
    r"|\x1b"                                # lone/unrecognized ESC
)


def _strip_non_sgr(text):
    """Remove every escape/control sequence EXCEPT SGR color codes (\\x1b[...m), so
    ansi_to_html still has color to render but stray cursor-move/erase/OSC sequences
    don't get HTML-escaped into literal garbage like '[K'."""
    def _keep_sgr(m):
        s = m.group(0)
        return s if _SGR_RE.fullmatch(s) else ""
    return _ESCAPE_TOKEN_RE.sub(_keep_sgr, text)


def _tokenize_sgr(line):
    """A line -> [('sgr', code), ('ch', char), ...], SGR runs kept as atomic tokens."""
    tokens, pos = [], 0
    for m in _SGR_RE.finditer(line):
        tokens.extend(("ch", c) for c in line[pos:m.start()])
        tokens.append(("sgr", m.group(0)))
        pos = m.end()
    tokens.extend(("ch", c) for c in line[pos:])
    return tokens


def _overlay_line(line):
    """Simulate a terminal line buffer so \\r/\\x08 overwrites resolve to the final
    displayed state instead of every intermediate frame. SGR tokens are zero-width and
    atomic: they never consume a column, and a column's overwrite also replaces whatever
    SGR was attached immediately before it (last write wins, colors included)."""
    buf, before, pending, col = [], {}, [], 0
    for kind, val in _tokenize_sgr(line):
        if kind == "sgr":
            pending.append(val)
        elif val == "\r":
            col = 0
        elif val == "\x08":
            col = col - 1 if col > 0 else 0
        else:
            if col >= len(buf):
                buf.extend(" " * (col - len(buf)))
                buf.append(val)
            else:
                buf[col] = val
            before[col] = pending
            pending = []
            col += 1
    out = []
    for i, ch in enumerate(buf):
        out.extend(before.get(i, ()))
        out.append(ch)
    out.extend(pending)
    return "".join(out)


def cook_terminal(text):
    """Cook raw captured terminal output into its final displayed state, so a --term/
    --tmux card shows what a human watching the terminal would see, not the raw byte
    stream. Two problems this fixes: (1) sqlmap/nmap/ffuf/nxc progress bars overwrite a
    line in place with \\r -- left raw, splitlines() turns every progress frame into its
    own line (a wall of spam) instead of the final clean result; (2) cursor-move/erase
    control sequences (\\x1b[K, \\x1b[2K, \\x1b[<n>A, OSC title-set, ...) aren't SGR so
    ansi_to_html doesn't understand them and they get HTML-escaped into literal garbage.
    SGR color codes are preserved throughout so colorized output still renders. Splits
    on '\\n' ONLY (never '\\r' -- that's the overwrite signal, not a line break).
    Fail-safe: never raises; returns the original text unchanged on any internal error."""
    try:
        stripped = _strip_non_sgr(text)
        return "\n".join(_overlay_line(ln) for ln in stripped.split("\n"))
    except Exception:
        return text


_ANSI_STRIP = re.compile(r"\x1b\[[0-9;]*m")
# interactive shell-prompt / echoed-command lines to drop from a captured pane. The
# Kali 2-line prompt (┌──( / └─) fuses with the typed command when capture-pane grabs
# it (the 'rootnmap -p-' mangling), and adds no evidence value -- the card's title bar
# already shows the command. Matched on the ANSI-stripped line.
_PROMPT_LINE = re.compile(
    "^(?:"
    "┌──\\(|"              # ┌──(   Kali top prompt (+ fused command)
    "└─|"                       # └─     Kali bottom prompt
    r"\S+@\S+:\S*\s*[#$]|"                # user@host:path$
    r"\[\S+@\S+[^\]]*\]\s*[#$]"           # [user@host dir]$
    ")")


def clean_term(text):
    """Strip shell-prompt + echoed-command lines and collapse blank runs from a captured
    pane so the card shows tool OUTPUT, not the fancy 2-line prompt fused with the typed
    command. ANSI-aware: matches on stripped text, keeps the original colored line."""
    out, blank = [], 0
    for ln in text.splitlines():
        bare = _ANSI_STRIP.sub("", ln)
        if _PROMPT_LINE.match(bare.lstrip("﻿ ")):
            continue
        if not bare.strip():
            blank += 1
            if blank > 1:
                continue
        else:
            blank = 0
        out.append(ln)
    while out and not _ANSI_STRIP.sub("", out[0]).strip():
        out.pop(0)
    while out and not _ANSI_STRIP.sub("", out[-1]).strip():
        out.pop()
    return "\n".join(out)


def colorize_session(text):
    """Colorize a captured terminal session so command / response / comment are visually
    distinct: `# ...` comments green, `$ ...` commands bold-cyan, curl `> ` request lines
    cyan, `< ` response-header lines blue, curl `* ` info lines dim; unprefixed output (the
    response body / tool output) keeps the default foreground. Lines already carrying ANSI
    are left as-is. Emits SGR codes that ansi_to_html then renders."""
    out = []
    for ln in text.split("\n"):
        bare = _ANSI_STRIP.sub("", ln).lstrip("﻿ ")
        if "\x1b[" in ln:
            out.append(ln)
        elif bare.startswith("# "):
            out.append("\x1b[32m" + ln + "\x1b[0m")     # comment = green
        elif bare.startswith("$ "):
            out.append("\x1b[1;36m" + ln + "\x1b[0m")   # command = bold cyan
        elif bare.startswith("> "):
            out.append("\x1b[36m" + ln + "\x1b[0m")     # curl request line = cyan
        elif bare.startswith("< "):
            out.append("\x1b[34m" + ln + "\x1b[0m")     # curl response header = blue
        elif bare.startswith("* "):
            out.append("\x1b[90m" + ln + "\x1b[0m")     # curl info = dim
        else:
            out.append(ln)
    return "\n".join(out)


def term_body(text, maxlines=120, cols=175):
    """(raw text, cap) -> (html body, VISUAL row count, truncated line count). The row
    count estimates wrapped rows (a long obfuscated-JS/scan line wraps to several visual
    rows) so term_height doesn't under-size and crop the card (the reveal was getting cut)."""
    lines = text.splitlines()
    truncated = 0
    if len(lines) > maxlines:
        truncated = len(lines) - maxlines
        lines = lines[:maxlines]
    visual = sum(max(1, (len(_ANSI_STRIP.sub("", ln)) + cols - 1) // cols) for ln in lines)
    return ansi_to_html("\n".join(lines)), visual, truncated


def term_html(body_html, cmd, truncated=0, url=None):
    """Wrap converted output in a self-contained dark terminal card. `url` adds a browser
    address-bar row so a card of a fetched web resource (a source/log/.md file) shows the
    URL it came from -- the source is self-identifying evidence, not an anonymous blob."""
    foot = ('\n<span class="tr">... (+%d lines truncated)</span>' % truncated) if truncated else ""
    addr = ("<div class='addr'>%s</div>" % _html.escape(url)) if url else ""
    return (
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        "html,body{margin:0;background:#0d1117}"
        ".win{margin:18px;border-radius:8px;overflow:hidden;"
        "box-shadow:0 8px 30px rgba(0,0,0,.5);border:1px solid #21262d}"
        ".bar{background:#161b22;padding:9px 14px;color:#9da5b4;"
        "font:13px ui-monospace,Menlo,Consolas,monospace;border-bottom:1px solid #21262d}"
        ".dot{height:11px;width:11px;border-radius:50%%;display:inline-block;margin-right:6px}"
        ".r{background:#ff5f56}.y{background:#ffbd2e}.g{background:#27c93f}"
        ".cmd{margin-left:10px;color:#d7dae0}"
        ".addr{background:#0d1117;color:#adbac7;padding:7px 14px;border-bottom:1px solid #21262d;"
        "font:12px ui-monospace,Menlo,Consolas,monospace;overflow:hidden;white-space:nowrap;"
        "text-overflow:ellipsis}"
        ".body{padding:14px 16px;color:#d7dae0;white-space:pre-wrap;word-break:break-word;"
        "font:13px/1.45 ui-monospace,Menlo,Consolas,monospace}"
        ".tr{color:#57606f}"
        "</style></head><body><div class='win'>"
        "<div class='bar'><span class='dot r'></span><span class='dot y'></span>"
        "<span class='dot g'></span><span class='cmd'>$ %s</span></div>"
        "%s<div class='body'>%s%s</div></div></body></html>"
        % (_html.escape(cmd or ""), addr, body_html, foot)
    )


def term_height(nlines, truncated=0):
    """Viewport height so chromium's fixed window doesn't crop the card. Bottom pad is
    generous: the last line is usually the payoff (a flag, a cred) and must never clip."""
    rows = nlines + (1 if truncated else 0)
    return 90 + rows * 20 + 64


def browser_frame(addr, page, is_srcdoc, height=900):
    """Wrap a web page in a browser-chrome frame that shows the URL in an address bar,
    so a page screenshot is self-identifying evidence (which URL it is). `page` is the
    iframe src URL (live) or the page HTML for srcdoc (authed --html)."""
    if is_srcdoc:
        esc = page.replace("&", "&amp;").replace('"', "&quot;")   # attribute-safe, keeps < >
        frame = '<iframe sandbox="allow-same-origin" srcdoc="%s"></iframe>' % esc
    else:
        frame = '<iframe src="%s"></iframe>' % _html.escape(addr, quote=True)
    return (
        "<!doctype html><html><head><meta charset='utf-8'><style>"
        "html,body{margin:0;background:#0d1117}"
        ".win{margin:14px;border-radius:10px;overflow:hidden;border:1px solid #30363d;"
        "box-shadow:0 10px 40px rgba(0,0,0,.5)}"
        ".bar{display:flex;align-items:center;background:#20262d;padding:9px 12px}"
        ".dot{height:12px;width:12px;border-radius:50%%;margin-right:7px}"
        ".addr{flex:1;margin-left:8px;background:#0d1117;color:#adbac7;border-radius:6px;"
        "padding:6px 12px;font:13px ui-monospace,Menlo,Consolas,monospace;overflow:hidden;"
        "white-space:nowrap;text-overflow:ellipsis}"
        "iframe{display:block;width:100%%;height:%dpx;border:0;background:#fff}"
        "</style></head><body><div class='win'><div class='bar'>"
        "<span class='dot' style='background:#ff5f56'></span>"
        "<span class='dot' style='background:#ffbd2e'></span>"
        "<span class='dot' style='background:#27c93f'></span>"
        "<span class='addr'>%s</span></div>%s</div></body></html>"
        % (height, _html.escape(addr, quote=True), frame)
    )


def tmux_capture_cmd(target, history=False):
    """argv to dump a tmux pane for a given target (session:window, window_id @NN, or
    session:name). -e keeps ANSI colors; -J JOINS soft-wrapped lines so a long tool line
    (e.g. an 83-char nmap -sV row in an 80-col pane) isn't split mid-line in the card -- it
    reflows to the card's own (much wider) width instead. history=True adds `-S -` to grab the
    FULL scrollback (not just the visible rows), so long output is never truncated by the pane
    height -- the whole request/response/session is captured for a report-ready PoC."""
    hist = ["-S", "-"] if history else []
    return ["tmux", "capture-pane", "-J", "-p", "-e"] + hist + ["-t", target]


def x_session(who_text, home_root="/home", default_user="kali"):
    """Resolve (user, display, xauth) of the desktop session from `who` output.
    Looks for a login line with a (:N) display; falls back to the default user on :0."""
    for line in who_text.splitlines():
        m = re.search(r"\((:\d+(?:\.\d+)?)\)", line)
        if m and line.split():
            user = line.split()[0]
            return user, m.group(1), "%s/%s/.Xauthority" % (home_root, user)
    return default_user, ":0", "%s/%s/.Xauthority" % (home_root, default_user)


def seat_session_id(loginctl_text):
    """First systemd session id bound to seat0 (for loginctl unlock-session), or None."""
    for line in loginctl_text.splitlines():
        if "seat0" in line and line.split():
            return line.split()[0]
    return None


def x_env(user, display, xauth):
    """argv prefix to run an X client as the seat user in their session."""
    return ["sudo", "-u", user, "env", "DISPLAY=" + display, "XAUTHORITY=" + xauth]


def grab_screen_cmd(user, display, xauth, out):
    return x_env(user, display, xauth) + ["scrot", "-o", out]


def window_id_cmd(user, display, xauth, name):
    return x_env(user, display, xauth) + ["xdotool", "search", "--onlyvisible", "--name", name]


def grab_window_cmd(user, display, xauth, wid, out):
    return x_env(user, display, xauth) + ["import", "-window", wid, out]


def wake_cmd(user, display, xauth):
    return x_env(user, display, xauth) + ["xset", "dpms", "force", "on"]


def unlock_cmd(session_id):
    return ["loginctl", "unlock-session", session_id]


def grab_x(out, window=None):
    """Run a scrot/import GUI grab into `out` on the VM. Wakes + unlocks the seat
    session first (best-effort). If `window` is given, target that app window; fall
    back to a full-screen grab when no matching window is found. Returns the
    subprocess result of the grab (for the size/return-code check in main)."""
    who = subprocess.run(["who"], capture_output=True, text=True, timeout=10).stdout
    user, display, xauth = x_session(who)
    # unlock (root) + wake (seat user), both best-effort
    try:
        lc = subprocess.run(["loginctl", "list-sessions", "--no-legend"],
                            capture_output=True, text=True, timeout=10).stdout
        sid = seat_session_id(lc)
        if sid:
            subprocess.run(unlock_cmd(sid), capture_output=True, timeout=10)
    except Exception:
        pass
    try:
        subprocess.run(wake_cmd(user, display, xauth), capture_output=True, timeout=10)
    except Exception:
        pass
    if window:
        ids = subprocess.run(window_id_cmd(user, display, xauth, window),
                             capture_output=True, text=True, timeout=10).stdout.split()
        if ids:
            return subprocess.run(grab_window_cmd(user, display, xauth, ids[0], out),
                                  capture_output=True, timeout=30)
        print("shot: window %r not found - grabbing full screen instead" % window,
              file=sys.stderr)
    return subprocess.run(grab_screen_cmd(user, display, xauth, out),
                          capture_output=True, timeout=30)


def rewrite_assets(html, base):
    """Make root-relative asset refs absolute so chromium fetches them from the target."""
    base = base.rstrip("/")
    html = re.sub(r'(\b(?:src|href)\s*=\s*["\'])/(?!/)', r"\1" + base + "/", html)
    html = re.sub(r'(url\(\s*["\']?)/(?!/)', r"\1" + base + "/", html)
    return html


def resolve_out(args):
    if args.out:
        return args.out
    if args.step is not None and args.slug:
        return os.path.join(args.dir or ".", slug_outname(args.step, args.slug))
    return None


def capture(url=None, html=None, html_str=None, out=None, base=None,
            width=1440, height=900, wait=0, timeout=45):
    target = url
    tmp = None
    if out and os.path.exists(out):
        try:
            os.unlink(out)
        except OSError:
            pass
    try:
        if html_str is not None:
            fd, tmp = tempfile.mkstemp(suffix=".html")
            os.write(fd, html_str.encode("utf-8", "ignore"))
            os.close(fd)
            target = "file://" + tmp
        elif html:
            data = open(html, encoding="utf-8", errors="ignore").read()
            if base:
                fd, tmp = tempfile.mkstemp(suffix=".html")
                os.write(fd, rewrite_assets(data, base).encode("utf-8", "ignore"))
                os.close(fd)
                target = "file://" + tmp
            else:
                target = "file://" + os.path.abspath(html)
        cmd = [chromium_bin(), "--headless", "--no-sandbox", "--disable-dev-shm-usage",
               "--hide-scrollbars", "--disable-gpu", "--ignore-certificate-errors",
               "--screenshot=" + out, "--window-size=%d,%d" % (width, height)]
        if wait:
            cmd.append("--virtual-time-budget=%d" % wait)
        cmd.append(target)
        return subprocess.run(cmd, capture_output=True, timeout=timeout)
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="capture a web page / PoC state to PNG (run on Kali)")
    ap.add_argument("url", nargs="?", help="page URL (live mode)")
    ap.add_argument("--html", help="render a saved HTML response instead (authed mode)")
    ap.add_argument("--base", help="with --html: rewrite root-relative asset URLs to this origin")
    ap.add_argument("--url-bar", dest="url_bar",
                    help="with --html: URL to show in the address bar (evidence). Live mode uses <url> automatically")
    ap.add_argument("--no-bar", dest="no_bar", action="store_true",
                    help="web modes: don't add the browser-chrome/URL address bar")
    ap.add_argument("--term", help="render raw tool output (a file, or - for stdin) as a terminal card")
    ap.add_argument("--tmux", help="capture a live tmux pane (session:name or @id) as a terminal card")
    ap.add_argument("--screen", action="store_true", help="grab the whole :0 desktop (scrot)")
    ap.add_argument("--window", help="grab a GUI window by name (xdotool+import), else full screen")
    ap.add_argument("--cmd", default="", help="command string shown in the terminal-card title bar")
    ap.add_argument("--maxlines", type=int, default=120, help="cap rendered lines (--term/--tmux)")
    ap.add_argument("--history", action="store_true",
                    help="--tmux: capture the FULL pane scrollback (-S -) so long output is never truncated")
    ap.add_argument("--raw", action="store_true",
                    help="--term/--tmux: keep shell-prompt lines (default strips them for a clean card)")
    ap.add_argument("--reqresp", action="store_true",
                    help="--term/--tmux: color the session so command / response / comment are distinct "
                         "(# green, $ cyan, curl >/< request/response)")
    ap.add_argument("-o", "--out", help="output PNG path")
    ap.add_argument("--step", type=int, help="step number for NN-slug.png naming")
    ap.add_argument("--slug", help="short slug for NN-slug.png naming")
    ap.add_argument("--dir", help="output dir when using --step/--slug (default .)")
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("--height", type=int, default=900)
    ap.add_argument("--wait", type=int, default=0, help="ms to let the page settle (virtual time)")
    ap.add_argument("--caption", default="")
    a = ap.parse_args(argv)
    if not (a.url or a.html or a.term or a.tmux or a.screen or a.window):
        ap.error("need <url>, --html, --term, --tmux, --screen, or --window")
    out = resolve_out(a)
    if not out:
        ap.error("need -o PATH or (--step N --slug S)")
    grab = bool(a.screen or a.window)
    try:
        if grab:
            proc = grab_x(out, window=a.window)
        elif a.tmux:
            cap = subprocess.run(tmux_capture_cmd(a.tmux, history=a.history), capture_output=True,
                                 text=True, timeout=15)
            if cap.returncode != 0:
                print("shot: tmux capture failed for %r: %s (use the window id @NN or the "
                      "sanitized tab name, not a dotted target)"
                      % (a.tmux, (cap.stderr or "").strip()[:200]), file=sys.stderr)
                return 1
            cooked = cook_terminal(cap.stdout)               # resolve \r/\x08 overwrites, strip control codes
            raw = cooked if a.raw else clean_term(cooked)    # drop the fused prompt lines
            if a.reqresp:
                raw = colorize_session(raw)                          # comment/command/response coloring
            body, nlines, truncated = term_body(raw, a.maxlines)
            proc = capture(html_str=term_html(body, a.cmd or a.tmux, truncated, url=a.url_bar),
                           out=out, width=a.width,
                           height=term_height(nlines, truncated) + (44 if a.url_bar else 0), wait=a.wait)
        elif a.term:
            raw = sys.stdin.read() if a.term == "-" else \
                open(a.term, encoding="utf-8", errors="ignore").read()
            raw = cook_terminal(raw)                          # resolve \r/\x08 overwrites, strip control codes
            if not a.raw:
                raw = clean_term(raw)
            if a.reqresp:
                raw = colorize_session(raw)
            body, nlines, truncated = term_body(raw, a.maxlines)
            proc = capture(html_str=term_html(body, a.cmd, truncated, url=a.url_bar),
                           out=out, width=a.width,
                           height=term_height(nlines, truncated) + (44 if a.url_bar else 0), wait=a.wait)
        else:
            addr = a.url or a.url_bar          # URL to show in the address bar
            if addr and not a.no_bar:
                if a.html:                     # authed page -> iframe srcdoc (with --base rewrite)
                    page = open(a.html, encoding="utf-8", errors="ignore").read()
                    if a.base:
                        page = rewrite_assets(page, a.base)
                    frame = browser_frame(addr, page, is_srcdoc=True, height=a.height)
                else:                          # live page -> iframe src=url
                    frame = browser_frame(addr, a.url, is_srcdoc=False, height=a.height)
                proc = capture(html_str=frame, out=out, width=a.width, height=a.height + 70,
                               wait=a.wait or 400)
            else:
                proc = capture(url=a.url, html=a.html, out=out, base=a.base,
                               width=a.width, height=a.height, wait=a.wait)
    except Exception as e:
        print("shot: FAILED: %s" % e, file=sys.stderr)
        return 1
    sz = os.path.getsize(out) if os.path.exists(out) else 0
    if not sz:
        print("shot: no PNG produced (grab failed? tmux target wrong? chromium missing?)",
              file=sys.stderr)
        return 1
    if not grab:
        # chromium can exit 0 while rendering its OWN error page into a sized PNG.
        stderr = (proc.stderr or b"").decode("utf-8", "ignore") if proc else ""
        markers = ("net::ERR", "ERROR:headless", "Navigation failed")
        bad = next((l.strip() for l in stderr.splitlines() if any(m in l for m in markers)), None)
        if bad:
            print("shot: FAILED nav (%s) - host unreachable / wrong url; the PNG is likely "
                  "an error page" % bad[:200], file=sys.stderr)
            return 1
    print("saved %s (%d bytes)" % (out, sz))
    print("md: %s" % md_ref(os.path.basename(out), a.caption))
    return 0


if __name__ == "__main__":
    sys.exit(main())
