"""autocard.sh: the always-on live recon-card script fired detached by the Stop hook.
Offline tests - the VM/tmux path can't run here, so we assert the fail-open guards."""
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SC = os.path.join(REPO, "scripts", "autocard.sh")


def _run(*args, env=None):
    return subprocess.run(["bash", SC, *args], capture_output=True, text=True,
                          env=env, timeout=15)


def test_syntax_valid():
    r = subprocess.run(["bash", "-n", SC], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_no_arg_exits_clean():
    assert _run().returncode == 0


def test_unknown_engagement_exits_clean():
    # non-existent engagement dir -> exits before any VM call (VM_SH stubbed for safety)
    env = dict(os.environ, VM_SH="/bin/true")
    assert _run("does-not-exist-xyz-123", env=env).returncode == 0


def test_existing_eng_no_tabs_exits_clean(tmp_path):
    # a real engagement dir but the VM bridge returns nothing (no tmux session) -> exit 0, no crash
    eng = "boxx"
    d = os.path.join(REPO, "targets", eng)
    made = not os.path.isdir(d)
    if made:
        os.makedirs(d, exist_ok=True)
    try:
        env = dict(os.environ, VM_SH="/bin/true")   # prints nothing -> empty window list
        r = _run(eng, env=env)
        assert r.returncode == 0
        assert not os.path.exists(os.path.join(d, ".carded-tabs")) or \
            open(os.path.join(d, ".carded-tabs")).read().strip() == ""
    finally:
        if made:
            import shutil
            shutil.rmtree(d, ignore_errors=True)
