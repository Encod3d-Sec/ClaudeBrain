"""Tests for scripts/wiki-query.sh (deterministic wiki-first fallback wrapper).

Only the fast, qmd-free paths are exercised here (arg parsing + missing-qmd), so the
suite never loads the embedding model. The live query is covered manually.
"""
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WQ = os.path.join(REPO, "scripts", "wiki-query.sh")


def _run(args, env=None):
    return subprocess.run(["bash", WQ] + args, capture_output=True, text=True,
                          env=env, timeout=20)


def test_usage_error_without_query():
    r = _run([])
    assert r.returncode == 2
    assert "usage:" in r.stderr


def test_missing_qmd_fails_loud_with_grep_hint():
    # strip qmd from PATH -> must fail loudly (exit 1) and point at the grep fallback,
    # never silently succeed with no results.
    env = dict(os.environ, PATH="/usr/bin:/bin")
    r = _run(["some query"], env=env)
    assert r.returncode == 1
    assert "qmd not installed" in r.stderr
    assert "grep -rin" in r.stderr


def test_keyword_flag_is_accepted():
    # -k must parse (not be treated as the query); with qmd absent it still reaches the
    # missing-qmd guard rather than an arg-parse error.
    env = dict(os.environ, PATH="/usr/bin:/bin")
    r = _run(["-k", "CVE-2023-23752"], env=env)
    assert r.returncode == 1 and "qmd not installed" in r.stderr
