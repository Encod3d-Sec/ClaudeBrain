"""Tests for scripts/browser.sh (debuggable chromium + CDP endpoint for chrome-devtools-mcp).

Only the fast, VM-free paths are exercised: arg handling and the security invariant. Actually
starting chromium needs the Kali VM and is covered manually via `browser.sh start`.
"""
import os
import pathlib
import re
import subprocess

VAULT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = VAULT / "scripts" / "browser.sh"


def _run(args):
    return subprocess.run(["bash", str(SCRIPT)] + args, capture_output=True, text=True,
                          timeout=30)


def test_exists_executable():
    assert SCRIPT.exists()
    assert os.access(SCRIPT, os.X_OK)


def test_usage_no_args():
    assert _run([]).returncode != 0


def test_unknown_command_fails():
    r = _run(["frobnicate"])
    assert r.returncode != 0
    assert "unknown command" in r.stderr


def test_unknown_host_fails():
    r = _run(["start", "--host", "moon"])
    assert r.returncode != 0
    assert "kali or windows" in r.stderr


def test_url_reports_loopback_and_honours_port():
    assert _run(["url"]).stdout.strip() == "http://127.0.0.1:9222"
    assert _run(["url", "--port", "9333"]).stdout.strip() == "http://127.0.0.1:9333"


def test_cdp_port_is_never_bound_to_all_interfaces():
    """The CDP port grants unauthenticated total control of the browser.

    It must only ever be bound to loopback and reached over an SSH forward. A
    `--remote-debugging-address=0.0.0.0` would hand every session in that browser to
    anything on the LAN, so guard against it being reintroduced as a "fix" for a
    connectivity problem. The literal 0.0.0.0 still appears in the refusal message that
    explains why we do not do this, so check executable lines only, not comments.
    """
    code = "\n".join(l for l in SCRIPT.read_text().splitlines()
                     if not l.lstrip().startswith("#"))
    assert not re.search(r"remote-debugging-address\s*=\s*0\.0\.0\.0", code)
    assert "remote-debugging-address=127.0.0.1" in code
