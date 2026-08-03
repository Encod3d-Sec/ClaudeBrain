"""Tests for scripts/wiki-query.sh (deterministic wiki-first fallback wrapper).

Only the fast, qmd-free paths are exercised here (arg parsing + missing-qmd), so the
suite never loads the embedding model. The live query is covered manually.
"""
import os
import subprocess
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WQ = os.path.join(REPO, "scripts", "wiki-query.sh")


def _run(args, env=None):
    # bash by absolute path: the qmd-free env below empties PATH, so PATH lookup
    # of "bash" would fail before the script ever runs.
    return subprocess.run(["/bin/bash", WQ] + args, capture_output=True, text=True,
                          env=env, timeout=20)


def _qmd_free_env():
    """An env where `command -v qmd` genuinely finds nothing.

    Setting PATH=/usr/bin:/bin does NOT hide qmd: `bun install -g` drops symlinks
    into /usr/bin and /bin on some machines, so the missing-qmd guard was never
    reached and these tests ran a real (slow) query instead. Point PATH at an empty
    directory so absence is guaranteed on every machine.
    """
    return dict(os.environ, PATH=tempfile.mkdtemp(prefix="wq-noqmd-"))


def test_usage_error_without_query():
    r = _run([])
    assert r.returncode == 2
    assert "usage:" in r.stderr


def test_missing_qmd_fails_loud_with_grep_hint():
    # strip qmd from PATH -> must fail loudly (exit 1) and point at the grep fallback,
    # never silently succeed with no results.
    env = _qmd_free_env()
    r = _run(["some query"], env=env)
    assert r.returncode == 1
    assert "qmd not installed" in r.stderr
    assert "grep -rin" in r.stderr


def test_keyword_flag_is_accepted():
    # -k must parse (not be treated as the query); with qmd absent it still reaches the
    # missing-qmd guard rather than an arg-parse error.
    env = _qmd_free_env()
    r = _run(["-k", "CVE-2023-23752"], env=env)
    assert r.returncode == 1 and "qmd not installed" in r.stderr
