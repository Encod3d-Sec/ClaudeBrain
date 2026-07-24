"""burp-transport.sh: the three-branch transport decision (native|bridge|down).
Offline -- the bridge probe is stubbed via VM_SH so no real SSH dial happens."""
import os
import pathlib
import subprocess

RESOLVER = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "burp" / "burp-transport.sh"


def _run(env_extra=None, args=()):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(["bash", str(RESOLVER), *args], capture_output=True, text=True, env=env)


def test_native_when_flagged():
    r = _run({"BURP_NATIVE": "1"})
    assert r.returncode == 0
    assert r.stdout.strip() == "native"
    assert "native" in r.stderr.lower()


def test_bridge_when_cli_lists_tools(tmp_path):
    # a stub VM_SH that echoes a fake tool list -> the bridge branch
    stub = tmp_path / "vm.sh"
    stub.write_text("#!/usr/bin/env bash\necho 'create_repeater_tab  x'\necho 'send_http1_request  y'\n")
    stub.chmod(0o755)
    r = _run({"VM_SH": str(stub)})  # BURP_NATIVE unset
    assert r.returncode == 0
    assert r.stdout.strip() == "bridge"


def test_down_when_bridge_silent(tmp_path):
    stub = tmp_path / "vm.sh"
    stub.write_text("#!/usr/bin/env bash\nexit 0\n")  # no tools
    stub.chmod(0o755)
    r = _run({"VM_SH": str(stub)})
    assert r.returncode == 3
    assert r.stdout.strip() == "down"
    assert "restart" in r.stderr.lower()


def test_dry_run_never_probes_the_bridge(tmp_path):
    # --dry-run must NOT invoke VM_SH; a stub that screams proves it was skipped
    stub = tmp_path / "vm.sh"
    stub.write_text("#!/usr/bin/env bash\necho 'SHOULD_NOT_RUN' >&2\nexit 1\n")
    stub.chmod(0o755)
    r = _run({"VM_SH": str(stub)}, args=("--dry-run",))
    assert "SHOULD_NOT_RUN" not in r.stderr
    assert r.stdout.strip() == "down"   # native not flagged + no probe -> down
    assert r.returncode == 3
