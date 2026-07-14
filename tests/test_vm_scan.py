"""vm-scan.sh --dry-run tests (no VM; asserts the remote tmux script it would run)."""
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "vm-scan.sh")


def dry(*args):
    p = subprocess.run(["bash", SCRIPT, "--dry-run", *args],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return p.stdout


def test_sanitizes_dots_colons_spaces_in_name():
    out = dry("eng1", "demo-web-10.0.0.5", "nmap", "-sV", "10.0.0.5")
    assert "demo-web-10-0-0-5" in out          # dots -> dashes in the tab name
    assert "10.0.0.5" not in out.split("send-keys", 1)[0]   # name portion has no dots
    assert "new-window" in out and "#{window_id}" in out    # id-based targeting
    assert "send-keys" in out and "nmap -sV 10.0.0.5" in out


def test_session_and_multiweb_name():
    out = dry("eng1", "acme-web-app.example.com", "nuclei", "-u", "https://app.example.com")
    assert "acme-web-app-example-com" in out
    assert "has-session -t eng1" in out or "new-session -d -s eng1" in out


# ---- Area 2 (always-capture-evidence): .pending-tmux marker on a real (non-dry) launch ----

def test_records_pending_tmux_entry(tmp_path):
    # fake vault: targets/active.md pointing at an engagement dir, so vm-scan.sh can
    # resolve it without touching the real (private) targets/ tree.
    vault = tmp_path / "vault"
    eng = vault / "targets" / "eng1"
    eng.mkdir(parents=True)
    (vault / "targets" / "active.md").write_text("eng1\n")
    # fake VM_SH: ignore the remote tmux script, exit 0 (mirrors loop-driver's fakevm.sh)
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\nexit 0\n")
    os.chmod(str(stub), 0o755)
    env = dict(os.environ, VM_SH=str(stub), CLAUDEBRAIN_VAULT=str(vault))
    p = subprocess.run(["bash", SCRIPT, "eng1", "10.0.0.5", "nmap", "-sV", "10.0.0.5"],
                       capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stderr
    marker = eng / ".pending-tmux"
    assert marker.is_file()
    assert marker.read_text().strip() == "eng1:10-0-0-5"


def test_pending_tmux_appends_multiple_launches(tmp_path):
    vault = tmp_path / "vault"
    eng = vault / "targets" / "eng1"
    eng.mkdir(parents=True)
    (vault / "targets" / "active.md").write_text("eng1\n")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\nexit 0\n")
    os.chmod(str(stub), 0o755)
    env = dict(os.environ, VM_SH=str(stub), CLAUDEBRAIN_VAULT=str(vault))
    subprocess.run(["bash", SCRIPT, "eng1", "10.0.0.5", "nmap", "-sV", "10.0.0.5"],
                   capture_output=True, text=True, env=env)
    subprocess.run(["bash", SCRIPT, "eng1", "10.0.0.6", "nmap", "-sV", "10.0.0.6"],
                   capture_output=True, text=True, env=env)
    lines = (eng / ".pending-tmux").read_text().splitlines()
    assert lines == ["eng1:10-0-0-5", "eng1:10-0-0-6"]


def test_dry_run_does_not_write_pending_tmux(tmp_path):
    # --dry-run must stay side-effect-free (no VM call, no marker write)
    vault = tmp_path / "vault"
    eng = vault / "targets" / "eng1"
    eng.mkdir(parents=True)
    (vault / "targets" / "active.md").write_text("eng1\n")
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))
    p = subprocess.run(["bash", SCRIPT, "--dry-run", "eng1", "10.0.0.5", "nmap", "-sV", "10.0.0.5"],
                       capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stderr
    assert not (eng / ".pending-tmux").exists()


def test_no_active_engagement_skips_marker(tmp_path):
    # no targets/active.md / no matching engagement dir -> fail-open, no marker, no crash
    vault = tmp_path / "vault"
    (vault / "targets").mkdir(parents=True)
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\nexit 0\n")
    os.chmod(str(stub), 0o755)
    env = dict(os.environ, VM_SH=str(stub), CLAUDEBRAIN_VAULT=str(vault))
    p = subprocess.run(["bash", SCRIPT, "eng1", "10.0.0.5", "nmap", "-sV", "10.0.0.5"],
                       capture_output=True, text=True, env=env)
    assert p.returncode == 0, p.stderr
