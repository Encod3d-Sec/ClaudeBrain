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


def _mock_env(tmp_path, tabs):
    """VM_SH mock: list-windows -> the given tabs; capture-pane -> a finished shell prompt.
    CAPTURE_SH mock: always succeeds (record each card call to a file)."""
    vm = tmp_path / "vm.sh"
    vm.write_text(
        "#!/usr/bin/env bash\n"
        'case "$1" in\n'
        f'  *list-windows*) printf "%s\\n" {" ".join(tabs)} ;;\n'
        '  *capture-pane*) printf "\\u2514\\u2500# " ;;\n'   # kali prompt = "finished"
        'esac\n')
    vm.chmod(0o755)
    cap = tmp_path / "capture.sh"
    calls = tmp_path / "calls.log"
    cap.write_text("#!/usr/bin/env bash\n"
                   f'printf "%s\\n" "$4" >> "{calls}"\n'   # $4 = the tab
                   "exit 0\n")
    cap.chmod(0o755)
    return dict(os.environ, VM_SH=str(vm), CAPTURE_SH=str(cap)), calls


def _tmp_eng(tmp_path, name="boxcap"):
    d = os.path.join(REPO, "targets", name)
    os.makedirs(d, exist_ok=True)
    return name, d


def test_caps_tabs_per_run(tmp_path):
    # 4 finished tabs, AUTOCARD_MAX=2 -> only 2 carded this run; the rest wait for next run.
    name, d = _tmp_eng(tmp_path)
    open(os.path.join(d, ".carded-tabs"), "w").close()
    try:
        env, calls = _mock_env(tmp_path, ["nmap", "nxc", "asrep", "crack"])
        env["AUTOCARD_MAX"] = "2"
        r = _run(name, env=env)
        assert r.returncode == 0
        carded = open(os.path.join(d, ".carded-tabs")).read().split()
        assert len(carded) == 2, f"expected 2 cards/run, got {carded}"
        # a second run cards the next 2 (idempotent: no tab carded twice)
        _run(name, env=env)
        carded2 = open(os.path.join(d, ".carded-tabs")).read().split()
        assert len(carded2) == 4 and len(set(carded2)) == 4, carded2
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def test_already_carded_tab_skipped(tmp_path):
    # a tab already in .carded-tabs is never re-carded
    name, d = _tmp_eng(tmp_path, "boxcap2")
    with open(os.path.join(d, ".carded-tabs"), "w") as f:
        f.write("nmap\n")
    try:
        env, calls = _mock_env(tmp_path, ["nmap"])
        env["AUTOCARD_MAX"] = "5"
        _run(name, env=env)
        assert not calls.exists(), "already-carded tab must not trigger a capture call"
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
