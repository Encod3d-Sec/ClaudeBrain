"""shot.py --highlight: apply_highlight wraps the whole matching LINE in a highlight SGR,
and ansi_to_html now renders the background color so the highlight is visible in the card."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import shot  # noqa: E402


def test_apply_highlight_wraps_the_whole_matching_line():
    out = shot.apply_highlight("noise line\nuid=0(root) www-data here\ntail", r"www-data|uid=0")
    assert "\x1b[30;43muid=0(root) www-data here\x1b[0m" in out
    # non-matching lines are left untouched
    assert "\nnoise line\n" in "\n" + out + "\n"
    assert "\x1b[30;43mnoise line" not in out


def test_apply_highlight_is_case_insensitive():
    assert "\x1b[30;43mWWW-DATA line\x1b[0m" in shot.apply_highlight("WWW-DATA line", "www-data")


def test_apply_highlight_none_or_empty_is_noop():
    assert shot.apply_highlight("abc", None) == "abc"
    assert shot.apply_highlight("abc", "") == "abc"


def test_apply_highlight_bad_regex_falls_back_to_literal():
    # unbalanced paren is not valid regex -> match the literal string instead of crashing
    out = shot.apply_highlight("a(b c\nother", "(b")
    assert "\x1b[30;43ma(b c\x1b[0m" in out


def test_ansi_to_html_renders_background_color():
    html = shot.ansi_to_html("x\x1b[30;43mHIT\x1b[0my")
    assert "background-color:#e5c07b" in html   # 43 = yellow highlight
    assert "HIT" in html
