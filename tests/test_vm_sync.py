"""Tests for scripts/vm-sync.sh: push a vault script to /opt/arsenal on the VM when missing.
Mocks the VM bridge with a fake vm.sh (same pattern as tests/test_vm.py / test_vm_scan.py):
the fake ignores the remote command and echoes a fixed marker so we exercise the sync logic
without a real VM."""
import os
import stat
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM_SYNC = os.path.join(REPO, "scripts", "vm-sync.sh")


def _fake_vm(tmp_path, echo):
    p = tmp_path / "vm.sh"
    p.write_text("#!/usr/bin/env bash\necho %s\n" % echo)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def _run(vm, *args):
    env = {**os.environ, "VM_SH": vm}
    return subprocess.run(["bash", VM_SYNC, *args], capture_output=True, text=True, env=env)


def test_vm_sync_skips_when_present(tmp_path):
    # fake VM reports the file already there -> no push, exit 0
    r = _run(_fake_vm(tmp_path, "EXISTS"), "shot.py")
    assert r.returncode == 0
    assert "already in /opt/arsenal" in r.stdout


def test_vm_sync_pushes_when_missing(tmp_path):
    # fake VM never reports EXISTS -> proceed to push, which echoes SYNCED
    r = _run(_fake_vm(tmp_path, "SYNCED"), "shot.py")
    assert r.returncode == 0
    assert "SYNCED" in r.stdout


def test_vm_sync_rejects_missing_arg(tmp_path):
    r = _run(_fake_vm(tmp_path, "EXISTS"))
    assert r.returncode != 0


def test_vm_sync_rejects_unknown_script(tmp_path):
    r = _run(_fake_vm(tmp_path, "EXISTS"), "no-such-script-xyz.sh")
    assert r.returncode != 0
    assert "not found" in (r.stdout + r.stderr)
