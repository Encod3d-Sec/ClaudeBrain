"""capture.sh mode dispatch (bash). Offline: these paths exit at arg-check before any vm.sh call."""
import subprocess
import pathlib

CAP = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "capture.sh"


def _run(*args):
    return subprocess.run(["bash", str(CAP), *args], capture_output=True, text=True)


def test_web_is_a_known_mode():
    # too few args -> the web usage line, proving mode_web is dispatched (not "unknown mode")
    r = _run("web", "eng")  # 2 args, web needs >=3
    assert r.returncode == 2
    assert "capture.sh web <eng> <slug> <url>" in r.stderr
    assert "unknown mode" not in r.stderr


def test_help_lists_web():
    r = _run("--help")
    assert "web  <eng> <slug> <url>" in r.stderr


def test_unknown_mode_still_rejected():
    r = _run("bogus")
    assert r.returncode == 2
    assert "unknown mode" in r.stderr
