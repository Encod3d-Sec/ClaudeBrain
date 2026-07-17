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


# (Area 2 .pending-tmux marker removed: loop-driver + recon-capture tmux staging that
# consumed it are deleted, so vm-scan.sh no longer writes the marker.)
