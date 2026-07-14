"""End-to-end test for the publish leak gate (scripts/check-leaks.sh).

Builds a throwaway git repo with an engagement dir name as the client marker and
asserts the gate stays clean when no tracked file mentions it, then fails (exit 1)
once a tracked file leaks it.
"""
import os
import shutil
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True)


def _seed_repo(tmp_path):
    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    (repo / "skills" / "hooks").mkdir(parents=True)
    (repo / "docs").mkdir(parents=True)
    shutil.copy(os.path.join(REPO, "scripts", "check-leaks.sh"), repo / "scripts" / "check-leaks.sh")
    # _engagement is imported by the scope.md marker step; copy so it doesn't crash
    shutil.copy(os.path.join(REPO, "skills", "hooks", "_engagement.py"),
                repo / "skills" / "hooks" / "_engagement.py")
    (repo / "targets" / "zynocorp-xy7").mkdir(parents=True)   # engagement dir = client marker
    (repo / ".gitignore").write_text("targets/\n", encoding="utf-8")
    (repo / "docs" / "ok.md").write_text("nothing sensitive here\n", encoding="utf-8")
    _run("git init -q && git config user.email a@b.c && git config user.name t "
         "&& git add -A && git commit -qm init", repo)
    return repo


def test_check_leaks_passes_when_clean(tmp_path):
    repo = _seed_repo(tmp_path)
    r = _run("bash scripts/check-leaks.sh", repo)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout


def test_check_leaks_fails_on_marker_in_tracked_file(tmp_path):
    repo = _seed_repo(tmp_path)
    (repo / "docs" / "leak.md").write_text("deploy notes for zynocorp-xy7 prod\n", encoding="utf-8")
    _run("git add -A && git commit -qm leak", repo)
    r = _run("bash scripts/check-leaks.sh", repo)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "zynocorp-xy7" in r.stdout and "LEAK" in r.stdout


def _filemode_vault(tmp_path):
    """Vault with the script + _engagement copied and one engagement dir (the client
    marker). No git needed: --file mode never git-greps."""
    v = tmp_path / "v"
    (v / "scripts").mkdir(parents=True)
    (v / "skills" / "hooks").mkdir(parents=True)
    shutil.copy(os.path.join(REPO, "scripts", "check-leaks.sh"), v / "scripts" / "check-leaks.sh")
    shutil.copy(os.path.join(REPO, "skills", "hooks", "_engagement.py"),
                v / "skills" / "hooks" / "_engagement.py")
    (v / "targets" / "clientx").mkdir(parents=True)   # engagement dir = client marker
    return v


def test_check_leaks_file_mode_flags_marker(tmp_path):
    v = _filemode_vault(tmp_path)
    body = v / "body.md"
    body.write_text("deploy notes for clientx prod\n", encoding="utf-8")
    r = _run("bash scripts/check-leaks.sh --file " + str(body), v)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "clientx" in r.stdout and "FAIL" in r.stdout


def test_check_leaks_file_mode_clean(tmp_path):
    v = _filemode_vault(tmp_path)
    body = v / "body.md"
    body.write_text("| AcmeRouter | any | admin | admin | vendor | web UI |\n", encoding="utf-8")
    r = _run("bash scripts/check-leaks.sh --file " + str(body), v)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout


def test_check_leaks_file_mode_missing_path_fails_closed(tmp_path):
    """A nonexistent/unreadable candidate must fail the gate, not report clean."""
    v = _filemode_vault(tmp_path)
    missing = v / "does-not-exist.md"
    r = _run("bash scripts/check-leaks.sh --file " + str(missing), v)
    assert r.returncode != 0, r.stdout + r.stderr
    assert "clean" not in r.stdout
    assert "FAIL" in (r.stdout + r.stderr)


def test_check_leaks_bare_file_flag_fails(tmp_path):
    """--file with no path argument must error out, not silently fall through
    to the default tracked-file scan."""
    v = _filemode_vault(tmp_path)
    r = _run("bash scripts/check-leaks.sh --file", v)
    assert r.returncode != 0, r.stdout + r.stderr
    assert "clean" not in r.stdout
