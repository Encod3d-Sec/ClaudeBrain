"""autocard.sh AUTOCARD_ALL close-out sweep: cards EVERY tab (still-running scans + never-finishing
listener tabs included), bypassing both the per-run cap AND the finished-prompt gate. This is the
hardwire for the recurring "recon cards missing at close-out on a fast box" drift. Offline: the
VM bridge + capture.sh are mocked."""
import os
import shutil
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SC = os.path.join(REPO, "scripts", "autocard.sh")


def _run(name, env):
    return subprocess.run(["bash", SC, name], capture_output=True, text=True, env=env, timeout=20)


def _mock_running(tmp_path, tabs):
    """VM mock: list-windows -> tabs; capture-pane -> a STILL-RUNNING pane (no shell prompt, so
    the default finished-gate would skip it). capture.sh mock records each carded tab ($4)."""
    vm = tmp_path / "vm.sh"
    vm.write_text("#!/usr/bin/env bash\n"
                  'case "$1" in\n'
                  f'  *list-windows*) printf "%s\\n" {" ".join(tabs)} ;;\n'
                  '  *capture-pane*) printf "scanning in progress" ;;\n'
                  'esac\n')
    vm.chmod(0o755)
    cap = tmp_path / "capture.sh"
    calls = tmp_path / "calls.log"
    cap.write_text("#!/usr/bin/env bash\n" f'printf "%s\\n" "$4" >> "{calls}"\nexit 0\n')
    cap.chmod(0o755)
    return dict(os.environ, VM_SH=str(vm), CAPTURE_SH=str(cap)), calls


def _eng(name):
    d = os.path.join(REPO, "targets", name)
    os.makedirs(d, exist_ok=True)
    return name, d


def test_all_mode_cards_running_and_listener_tabs(tmp_path):
    # AUTOCARD_ALL cards all 5 still-running/listener tabs: cap (default 2) + finished-gate bypassed.
    name, d = _eng("boxsweepall")
    try:
        env, calls = _mock_running(tmp_path, ["ferox", "nuclei", "oob", "whatweb", "shell443"])
        env["AUTOCARD_ALL"] = "1"
        r = _run(name, env)
        assert r.returncode == 0, r.stderr
        carded = set(x for x in calls.read_text().splitlines() if x) if calls.exists() else set()
        assert carded == {"ferox", "nuclei", "oob", "whatweb", "shell443"}, carded
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_default_mode_still_skips_running_tabs(tmp_path):
    # WITHOUT AUTOCARD_ALL the pre-existing gate holds: still-running tabs (no prompt) are not carded.
    name, d = _eng("boxsweepdef")
    try:
        env, calls = _mock_running(tmp_path, ["ferox", "nuclei"])
        r = _run(name, env)
        assert r.returncode == 0, r.stderr
        carded = [x for x in calls.read_text().splitlines() if x] if calls.exists() else []
        assert carded == [], carded
    finally:
        shutil.rmtree(d, ignore_errors=True)
