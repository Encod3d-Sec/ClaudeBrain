import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "vm-provision.sh")


def test_list_has_required_packages():
    p = subprocess.run(["bash", SCRIPT, "--list"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    pkgs = set(p.stdout.split())
    # capture deps (original purpose)
    for need in ("tmux", "scrot", "xdotool", "imagemagick", "x11-utils", "xauth"):
        assert need in pkgs, "missing capture dep %s in provision list" % need
    # recon/test toolchain the nudges depend on (httpx-toolkit = ProjectDiscovery httpx)
    for need in ("httpx-toolkit", "subfinder", "naabu", "katana", "dalfox", "sqlmap",
                 "swaks", "trufflehog", "seclists"):
        assert need in pkgs, "missing recon tool %s in provision list" % need
