"""wl-add.sh leak-safe wordlist filter tests.

wl-add.sh appends generic tokens to a harness wordlist ($HERE/wordlists/*.txt),
deduped + sorted, behind a leak-safe filter (char-class allowlist, length cap,
IP-ish reject, fs/sensitive stop-word reject) so client/box-specific markers
never enter the shared, tracked wordlists. This exercises each reject branch.

Each test runs an ISOLATED COPY of the script from tmp_path, so $HERE resolves to
the throwaway dir and writes land in tmp_path/wordlists/ - never the tracked
scripts/wordlists/ tree.
"""
import os
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "wl-add.sh")


@pytest.fixture
def wl(tmp_path):
    """Copy wl-add.sh into an isolated dir + pre-create its wordlists/ dir.
    Returns (run, wldir): run(kind, *words) -> CompletedProcess."""
    script = tmp_path / "wl-add.sh"
    shutil.copy(SCRIPT, script)
    wldir = tmp_path / "wordlists"
    wldir.mkdir()

    def run(kind, *words):
        return subprocess.run(["bash", str(script), kind, *words],
                              capture_output=True, text=True)
    return run, wldir


def _paths_file(wldir):
    f = wldir / "harness-paths.txt"
    return f.read_text() if f.exists() else ""


def test_accepts_normal_path_token(wl):
    # (a) a plain generic wordlist token is accepted and written
    run, wldir = wl
    p = run("paths", "customapi")
    assert p.returncode == 0, p.stderr
    assert "+1 new" in p.stdout
    assert "customapi" in _paths_file(wldir).splitlines()


def test_rejects_ip_like_token(wl):
    # (b) an IP-address-like token is rejected by the IP-ish guard
    run, wldir = wl
    p = run("paths", "192.168.1.1")
    assert p.returncode == 0, p.stderr
    assert "skip (IP-ish)" in p.stderr
    assert "192.168.1.1" not in _paths_file(wldir)


def test_rejects_stop_word_token(wl):
    # (c) a filesystem/sensitive stop-word (e.g. a mount name) is rejected
    run, wldir = wl
    p = run("paths", "etc")
    assert p.returncode == 0, p.stderr
    assert "skip (fs/sensitive)" in p.stderr
    assert "etc" not in _paths_file(wldir).splitlines()


def test_filters_client_looking_token(wl):
    # (d) a client-looking token (host/email marker with punctuation) fails the
    #     char-class allowlist and is filtered out of the shared wordlist
    run, wldir = wl
    p = run("paths", "admin@corp.local")
    assert p.returncode == 0, p.stderr
    assert "skip (bad chars)" in p.stderr
    assert "admin@corp.local" not in _paths_file(wldir)


def test_rejects_overlong_token(wl):
    # length cap (>40 chars) rejects a long client-specific blob
    run, wldir = wl
    p = run("paths", "a" * 41)
    assert p.returncode == 0, p.stderr
    assert "skip (too long)" in p.stderr
    assert ("a" * 41) not in _paths_file(wldir)


def test_dedups_and_sorts_in_place(wl):
    # accepted tokens persist deduped + sorted across invocations
    run, wldir = wl
    run("paths", "beta", "alpha")
    run("paths", "beta", "gamma")   # beta already present -> not duplicated
    lines = [ln for ln in _paths_file(wldir).splitlines() if ln]
    assert lines == ["alpha", "beta", "gamma"]
