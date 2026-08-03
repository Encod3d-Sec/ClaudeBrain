"""vm.sh static source assertions (no VM; never opens a live SSH connection)."""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "setup", "vm.sh")


def read_source():
    with open(SCRIPT) as f:
        return f.read()


def test_ssh_invocation_has_control_multiplexing():
    src = read_source()
    assert "ControlMaster=auto" in src
    assert "ControlPath=" in src
    assert "ControlPersist=" in src


def test_ssh_invocation_regression_guard():
    src = read_source()
    assert "sshpass -p" in src
    assert "ConnectTimeout=8" in src
