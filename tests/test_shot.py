"""shot.py pure-logic tests (no browser; the chromium render is smoke-tested live on Kali)."""
import importlib.util
import os
import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location("shot", os.path.join(REPO, "scripts", "shot.py"))
shot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shot)


def test_slug_outname():
    assert shot.slug_outname(3, "Dashboard After SQLi") == "03-dashboard-after-sqli.png"
    assert shot.slug_outname(1, "login!! form") == "01-login-form.png"
    assert shot.slug_outname(12, "x" * 80).startswith("12-") and len(shot.slug_outname(12, "x" * 80)) <= 47
    assert shot.slug_outname(0, "") == "00-shot.png"


def test_md_ref():
    assert shot.md_ref("03-dash.png") == "![03-dash](poc/03-dash.png)"
    assert shot.md_ref("03-dash.png", "Admin dashboard") == "![Admin dashboard](poc/03-dash.png)"


def test_rewrite_assets():
    out = shot.rewrite_assets('<link href="/static/a.css"><img src="/x.png"> url(/bg.png)',
                              "http://t:5050/")
    assert 'href="http://t:5050/static/a.css"' in out
    assert 'src="http://t:5050/x.png"' in out
    assert "url(http://t:5050/bg.png)" in out
    # protocol-relative and absolute are left alone
    untouched = shot.rewrite_assets('<img src="//cdn/x"><img src="http://abs/y">', "http://t")
    assert "//cdn/x" in untouched and "http://abs/y" in untouched


def test_resolve_out():
    class A:
        out = None; step = 4; slug = "flag-page"; dir = "/tmp/poc"
    assert shot.resolve_out(A()) == "/tmp/poc/04-flag-page.png"
    A.out = "/tmp/explicit.png"
    assert shot.resolve_out(A()) == "/tmp/explicit.png"
    A.out = None; A.step = None
    assert shot.resolve_out(A()) is None


def test_main_requires_target_and_out():
    with pytest.raises(SystemExit):
        shot.main([])                       # no url/html
    with pytest.raises(SystemExit):
        shot.main(["http://x"])             # no -o / step+slug


def test_chromium_bin_returns_str():
    assert isinstance(shot.chromium_bin(), str)


# --- false-success guards (stale PNG + chromium error-page) ---

class _FakeProc:
    def __init__(self, stderr=b""):
        self.returncode, self.stderr, self.stdout = 0, stderr, b""


def _fake_run(make_png=False, stderr=b""):
    """Stand in for subprocess.run; optionally writes a PNG to the --screenshot= path."""
    def run(cmd, capture_output=True, timeout=None):
        if make_png:
            outp = next((a.split("=", 1)[1] for a in cmd if a.startswith("--screenshot=")), None)
            if outp:
                with open(outp, "wb") as f:
                    f.write(b"\x89PNG\r\n\x1a\n" + b"0" * 64)
        return _FakeProc(stderr=stderr)
    return run


def test_stale_png_not_false_success(tmp_path, monkeypatch):
    """A PNG left by a prior run must not mask a failed re-shoot."""
    out = str(tmp_path / "03-x.png")
    with open(out, "wb") as f:
        f.write(b"\x89PNG" + b"0" * 100)                # stale image
    monkeypatch.setattr(shot.subprocess, "run", _fake_run(make_png=False))
    assert shot.main(["http://t/x", "-o", out]) == 1    # chromium produced nothing this run


def test_error_page_flagged_via_stderr(tmp_path, monkeypatch, capsys):
    """chromium exits 0 rendering an error page; stderr markers must flag it as failure."""
    out = str(tmp_path / "03-x.png")
    monkeypatch.setattr(shot.subprocess, "run", _fake_run(
        make_png=True,
        stderr=b"[0101/000000] Navigation to http://t failed: net::ERR_CONNECTION_REFUSED\n"))
    assert shot.main(["http://t/x", "-o", out]) == 1
    assert "FAILED nav" in capsys.readouterr().err


def test_successful_capture_reports_saved(tmp_path, monkeypatch, capsys):
    out = str(tmp_path / "03-x.png")
    monkeypatch.setattr(shot.subprocess, "run", _fake_run(make_png=True))
    assert shot.main(["http://t/x", "-o", out]) == 0
    assert "saved" in capsys.readouterr().out


def test_ansi_to_html_colors_and_escape():
    # green FG then reset, with HTML-sensitive payload
    html = shot.ansi_to_html("\x1b[32mopen\x1b[0m <tag> & done")
    assert "color:#8cc265" in html          # green mapped
    assert ">open</span>" in html
    assert "&lt;tag&gt; &amp; done" in html  # payload escaped, outside any span
    # bold
    assert "font-weight:bold" in shot.ansi_to_html("\x1b[1mHI\x1b[0m")
    # unknown SGR code is dropped, not rendered as text
    assert "48;5;21" not in shot.ansi_to_html("\x1b[48;5;21mx\x1b[0m")


def test_term_body_truncates_and_counts():
    text = "\n".join("line%d" % i for i in range(200))
    body, nlines, truncated = shot.term_body(text, maxlines=120)
    assert nlines == 120
    assert truncated == 80
    body2, n2, t2 = shot.term_body("a\nb\nc", maxlines=120)
    assert n2 == 3 and t2 == 0


def test_term_html_has_command_and_truncation_footer():
    html = shot.term_html("<span>x</span>", 'nmap -sV "T" & <x>', truncated=5)
    assert "<!doctype html" in html.lower()
    assert "nmap -sV" in html
    assert "&amp;" in html and "&lt;x&gt;" in html   # cmd escaped in title bar
    assert "+5 lines truncated" in html
    assert "+0 lines" not in shot.term_html("y", "cmd", truncated=0)


def test_term_html_shows_source_url():
    # a --term card of a fetched web resource shows the URL it came from
    html = shot.term_html("<span>x</span>", "GET app.log", url="http://ex.com/folder/folder/log.md")
    assert "http://ex.com/folder/folder/log.md" in html and "class='addr'" in html
    assert "class='addr'" not in shot.term_html("y", "cmd")   # no url -> no addr bar


def test_term_body_counts_wrapped_rows():
    # a single very long line (obfuscated JS) wraps to several visual rows -> bigger height,
    # so the card doesn't crop the reveal at the bottom
    _, rows_long, _ = shot.term_body("x" * 700, cols=175)
    assert rows_long >= 4
    _, rows_short, _ = shot.term_body("short", cols=175)
    assert rows_short == 1


def test_term_height_grows_with_lines():
    assert shot.term_height(120, 0) > shot.term_height(10, 0)
    assert shot.term_height(10, 1) > shot.term_height(10, 0)


def test_main_term_requires_out(monkeypatch, tmp_path):
    f = tmp_path / "o.txt"
    f.write_text("hello")
    with pytest.raises(SystemExit):
        shot.main(["--term", str(f)])   # no -o / step+slug


def test_tmux_capture_cmd():
    assert shot.tmux_capture_cmd("eng:demo-web-10-0-0-5") == \
        ["tmux", "capture-pane", "-J", "-p", "-e", "-t", "eng:demo-web-10-0-0-5"]
    assert shot.tmux_capture_cmd("@43") == ["tmux", "capture-pane", "-J", "-p", "-e", "-t", "@43"]


def test_main_tmux_requires_out():
    with pytest.raises(SystemExit):
        shot.main(["--tmux", "eng:demo"])   # no -o / step+slug


def test_x_session_parses_seat_line():
    who = ("kali     seat0        2026-06-29 01:37 (:0)\n"
           "kali     pts/1        2026-07-01 03:09 (10.0.0.9)\n")
    assert shot.x_session(who) == ("kali", ":0", "/home/kali/.Xauthority")
    # no seat line -> defaults
    assert shot.x_session("") == ("kali", ":0", "/home/kali/.Xauthority")
    # a different user on :1
    who2 = "bob      seat0   ... (:1)\n"
    assert shot.x_session(who2) == ("bob", ":1", "/home/bob/.Xauthority")


def test_seat_session_id():
    txt = ("  12 1000 kali -     23493   user    - no -\n"
           "   2 1000 kali seat0 4592    user    - no -\n")
    assert shot.seat_session_id(txt) == "2"
    assert shot.seat_session_id("no seat here") is None


def test_grab_command_builders():
    env = ["sudo", "-u", "kali", "env", "DISPLAY=:0", "XAUTHORITY=/home/kali/.Xauthority"]
    assert shot.x_env("kali", ":0", "/home/kali/.Xauthority") == env
    assert shot.grab_screen_cmd("kali", ":0", "/home/kali/.Xauthority", "/tmp/o.png") == \
        env + ["scrot", "-o", "/tmp/o.png"]
    assert shot.window_id_cmd("kali", ":0", "/home/kali/.Xauthority", "Burp Suite") == \
        env + ["xdotool", "search", "--onlyvisible", "--name", "Burp Suite"]
    assert shot.grab_window_cmd("kali", ":0", "/home/kali/.Xauthority", "@43", "/tmp/o.png") == \
        env + ["import", "-window", "@43", "/tmp/o.png"]
    assert shot.wake_cmd("kali", ":0", "/home/kali/.Xauthority") == env + ["xset", "dpms", "force", "on"]
    assert shot.unlock_cmd("2") == ["loginctl", "unlock-session", "2"]


def test_main_screen_requires_out():
    with pytest.raises(SystemExit):
        shot.main(["--screen"])            # no -o / step+slug


def test_tmux_capture_failure_returns_1(monkeypatch, tmp_path):
    class _R:
        returncode = 1
        stdout = ""
        stderr = "can't find pane: 0.0.5"
    monkeypatch.setattr(shot.subprocess, "run", lambda *a, **k: _R())
    rc = shot.main(["--tmux", "eng:T-web-192.0.2.10", "-o", str(tmp_path / "o.png")])
    assert rc == 1


# --- clean_term: fix the mangled Kali-prompt fusion in --tmux/--term cards ---

def test_clean_term_strips_kali_prompt_fusion():
    pane = ("nmap -p- T\n"
            "┌──(root㉿kali)-[~]\n"       # top prompt (fuses with the typed command)
            "└─# nmap -p- T\n"                # bottom prompt + echoed command
            "Starting Nmap 7.95\n"
            "22/tcp open ssh\n"
            "\n\n\n"
            "┌──(root㉿kali)-[~]\n"
            "└─# \n")
    out = shot.clean_term(pane)
    assert "┌──(" not in out and "└─" not in out    # prompt/fused lines gone
    assert "22/tcp open ssh" in out and "Starting Nmap 7.95" in out
    assert "\n\n\n" not in out                              # blank runs collapsed


def test_clean_term_keeps_plain_output():
    txt = "PORT     STATE SERVICE\n22/tcp   open  ssh\n1337/tcp open  waste"
    assert shot.clean_term(txt) == txt                      # no prompt -> unchanged


def test_clean_term_strips_userhost_prompt():
    out = shot.clean_term("kali@kali:~/x$ ffuf -u http://t/FUZZ\nFUZZ: admin [Status: 200]\n")
    assert "kali@kali" not in out
    assert "FUZZ: admin [Status: 200]" in out


# --- browser_frame: web screenshots show the URL in an address bar ---

def test_browser_frame_live_shows_url_and_iframe_src():
    fr = shot.browser_frame("http://10.1.1.1:1337/dashboard.php",
                            "http://10.1.1.1:1337/dashboard.php", is_srcdoc=False)
    assert "http://10.1.1.1:1337/dashboard.php" in fr        # URL visible in the bar
    assert "<iframe src=" in fr and "class='addr'" in fr


def test_browser_frame_srcdoc_is_attribute_safe():
    fr = shot.browser_frame("http://t/x", '<h1>Hi</h1> a & "b"', is_srcdoc=True)
    assert "srcdoc=" in fr
    assert "&quot;b&quot;" in fr and "a &amp; " in fr        # attr-escaped
    assert "<h1>Hi</h1>" in fr                               # tags preserved inside srcdoc


# --- cook_terminal: resolve \r/\x08 overwrites + strip non-SGR control codes ---

def test_cook_terminal_collapses_full_line_progress_rewrite():
    out = shot.cook_terminal("progress 10%\rprogress 50%\rprogress 100% done")
    assert out == "progress 100% done"


def test_cook_terminal_overlay_overwrites_only_leading_chars():
    # DONE overwrites the first 4 chars of "loading...", the tail survives
    assert shot.cook_terminal("loading...\rDONE") == "DONEing..."


def test_cook_terminal_backspace():
    assert shot.cook_terminal("keep\x08\x08xy") == "kexy"


def test_cook_terminal_strips_non_sgr_csi_erase_codes():
    out = shot.cook_terminal("a\x1b[Kb\x1b[2Kc")
    assert out == "abc"
    assert "\x1b[K" not in out and "[K" not in out and "[2K" not in out


def test_cook_terminal_keeps_sgr_color_codes():
    out = shot.cook_terminal("\x1b[32mgreen\x1b[0m done")
    assert "\x1b[32m" in out
    assert "green" in out and "done" in out


def test_cook_terminal_cr_collapse_preserves_color():
    # a realistic reprinted-progress-bar frame: each frame carries its own color wrap;
    # the \r-collapse must land on the final frame without eating/garbling the SGR codes
    text = "\x1b[33mworking 1%\x1b[0m\r\x1b[33mworking 100%\x1b[0m"
    out = shot.cook_terminal(text)
    assert "\r" not in out
    assert "\x1b[33m" in out
    assert "working 100%" in out


def test_cook_terminal_strips_osc_and_cursor_move_sequences():
    out = shot.cook_terminal("\x1b]0;title\x07before\x1b[3Aafter\x1b[?25lend")
    assert out == "beforeafterend"


def test_cook_terminal_strips_lone_escape():
    assert shot.cook_terminal("keep\x1bmoving") == "keepmoving"


def test_cook_terminal_multiline_block_collapses_only_progress_line():
    text = "normal line\nprogress 1%\rprogress 100%\nfinal line"
    out = shot.cook_terminal(text)
    assert "\r" not in out
    assert out == "normal line\nprogress 100%\nfinal line"


def test_cook_terminal_idempotent_on_clean_text():
    text = "PORT     STATE SERVICE\n22/tcp   open  ssh\n\x1b[32mopen\x1b[0m plain text, no control chars"
    assert shot.cook_terminal(text) == text


def test_cook_terminal_never_raises_on_weird_input():
    # fail-safe: must not raise on odd/malformed input; degrades gracefully
    for weird in ("", "\r", "\x08", "\x1b", "\x1b[", "\x1b]", "\x1b[9999999999999999999m"):
        shot.cook_terminal(weird)  # must not raise


def test_colorize_session_distinguishes_comment_command_response():
    # comment -> green(32), command -> bold cyan(1;36), curl >/< request/response, body default
    src = "# a comment\n$ curl -i http://t/\n> GET / HTTP/1.1\n< HTTP/1.1 200 OK\n* info\nplain body\n"
    out = shot.colorize_session(src)
    assert "\x1b[32m# a comment\x1b[0m" in out          # comment green
    assert "\x1b[1;36m$ curl -i http://t/\x1b[0m" in out  # command bold cyan
    assert "\x1b[36m> GET / HTTP/1.1\x1b[0m" in out      # request cyan
    assert "\x1b[34m< HTTP/1.1 200 OK\x1b[0m" in out     # response header blue
    assert "\x1b[90m* info\x1b[0m" in out                # curl info dim
    # unprefixed response body keeps default foreground (no SGR wrap)
    assert "\nplain body\n" in out or out.endswith("plain body")
    # a line already carrying ANSI is left untouched
    assert shot.colorize_session("\x1b[1mbold\x1b[0m") == "\x1b[1mbold\x1b[0m"
