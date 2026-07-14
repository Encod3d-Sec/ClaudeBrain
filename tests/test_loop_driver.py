"""Stop-hook loop-driver + OOB auto-correlation, via subprocess against a fixture vault."""
import json
import os
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS = os.path.join(REPO, "skills", "hooks")

OOB_HEADER = ("| token | sink | class | planted | status | source |\n"
              "|-------|------|-------|---------|--------|--------|\n")


def _run(script, payload, env):
    return subprocess.run(["python3", os.path.join(HOOKS, script)],
                          input=json.dumps(payload), capture_output=True, text=True,
                          env=env, timeout=20)


def _env(vault):
    return dict(os.environ, CLAUDEBRAIN_VAULT=str(vault))


def _eng(vault):
    return vault / "targets" / "acme"


# ---- loop-driver ----

def _mark_solved(eng):
    with open(eng / "state.md", "a", encoding="utf-8") as fh:
        fh.write("\n## STATUS: SOLVED\n")


def _assemble_walkthrough(eng):
    (eng / "walkthrough.md").write_text(_ASSEMBLED_WT, encoding="utf-8")


def test_recon_capture_flips_oob_on_callback(vault):
    eng = _eng(vault)
    (eng / "oob.md").write_text(
        OOB_HEADER + "| canary7x9 | http://x/?u= | ssrf | 2026-06-28 | waiting | |\n")
    # a poll command whose output contains the unique token label -> HIT
    payload = {"tool_name": "Bash",
               "tool_input": {"command": "curl -s https://oast.example/poll"},
               "tool_response": "received dns interaction canary7x9.oast.example from 9.9.9.9"}
    out = _run("recon-capture.py", payload, _env(vault)).stdout
    assert "OOB HIT auto-correlated" in out
    assert "HIT" in (eng / "oob.md").read_text()


# ---- drain_pending ----

def test_drain_pending_noop_when_empty(tmp_path):
    import importlib.util
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "loop_driver", os.path.join(REPO, "skills", "hooks", "loop-driver.py"))
    ld = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ld)
    d = tmp_path / "ENG"
    (d / "recon").mkdir(parents=True)
    assert ld.drain_pending(str(d)) == []          # no .pending dir
    (d / "recon" / ".pending").mkdir()
    assert ld.drain_pending(str(d)) == []          # empty .pending


def test_drain_cli_entrypoint(tmp_path):
    """--drain CLI renders staged txt to PNG without blocking (Fix 2b + Fix 3)."""
    import base64
    import sys
    ld_path = os.path.join(REPO, "skills", "hooks", "loop-driver.py")
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap -sV T\n22/tcp open ssh\n")
    # fake vm: ignores the remote command and emits a >=100-byte base64 blob
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    result = subprocess.run(
        [sys.executable, ld_path, "--drain", str(d)],
        capture_output=True, text=True,
        env={**os.environ, "VM_SH": str(stub)},
        timeout=30)
    assert result.returncode == 0
    assert (d / "recon" / "0001-nmap-abcd1234.png").exists()   # PNG written
    assert not list(pend.glob("*-nmap-*.txt"))                # staged txt consumed


def _load_loop_driver():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "loop_driver", os.path.join(REPO, "skills", "hooks", "loop-driver.py"))
    ld = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ld)
    return ld


# ---- Area 2 (always-capture-evidence): drain_pending_tmux() auto-grabs tmux scans ----

def test_drain_pending_tmux_noop_when_no_marker(tmp_path):
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    assert ld.drain_pending_tmux(str(d)) == []


def test_drain_pending_tmux_renders_and_clears_entry(tmp_path):
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    # fake vm: ignores the remote --tmux render command, emits a >=100-byte base64 blob
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert rendered == ["tmux-eng1-10-0-0-5.png"]
    assert (d / "recon" / "tmux-eng1-10-0-0-5.png").exists()
    assert not (d / ".pending-tmux").exists()          # entry cleared (marker removed)


def test_drain_pending_tmux_leaves_entry_on_unreachable_vm(tmp_path):
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    rendered = ld.drain_pending_tmux(str(d), vm="/nonexistent/vm.sh")
    assert rendered == []
    assert (d / ".pending-tmux").read_text().strip() == "eng1:10-0-0-5"  # fail-open: kept


def test_drain_pending_tmux_partial_failure_keeps_only_failed_entry(tmp_path):
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\neng1:10-0-0-6\n")
    calls = {"n": 0}
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    # first call (shot.py push) always succeeds; render calls: first entry ok, second fails
    stub = tmp_path / "fakevm.sh"
    stub.write_text(
        '#!/bin/bash\n'
        'case "$1" in\n'
        '  *10-0-0-5*) printf "%%s" "%s" ;;\n'
        '  *) printf "short" ;;\n'
        'esac\n' % big_b64)
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert rendered == ["tmux-eng1-10-0-0-5.png"]
    assert (d / ".pending-tmux").read_text().strip() == "eng1:10-0-0-6"


def test_drain_pending_tmux_retries_transient_failure_then_succeeds(tmp_path):
    """A render that returns < 100 bytes on the first 2 attempts then a valid PNG blob on
    the 3rd must still render -- _RENDER_RETRIES bounds the retry, not a single shot."""
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    counter = tmp_path / "count"
    stub = tmp_path / "fakevm.sh"
    stub.write_text(
        '#!/bin/bash\n'
        'case "$1" in\n'
        '  *--tmux*)\n'
        '    N=$(cat "%s" 2>/dev/null || echo 0)\n'
        '    N=$((N+1))\n'
        '    echo $N > "%s"\n'
        '    if [ "$N" -lt 3 ]; then printf "c2hvcnQ="; else printf "%%s" "%s"; fi\n'
        '    ;;\n'
        '  *) printf "" ;;\n'
        'esac\n' % (counter, counter, big_b64))
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert rendered == ["tmux-eng1-10-0-0-5.png"]
    assert not (d / ".pending-tmux").exists()             # entry cleared once it rendered
    assert (d / "recon" / "tmux-eng1-10-0-0-5.png").exists()
    assert int(counter.read_text().strip()) == 3           # 2 failures + 1 success = 3 attempts


def test_drain_pending_tmux_all_retries_fail_keeps_entry(tmp_path):
    """All _RENDER_RETRIES attempts returning < 100 bytes -> the entry stays staged in
    .pending-tmux for a later drain (fail-open), no crash, retried exactly the bound."""
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    counter = tmp_path / "count"
    stub = tmp_path / "fakevm.sh"
    stub.write_text(
        '#!/bin/bash\n'
        'case "$1" in\n'
        '  *--tmux*)\n'
        '    N=$(cat "%s" 2>/dev/null || echo 0)\n'
        '    N=$((N+1))\n'
        '    echo $N > "%s"\n'
        '    printf "c2hvcnQ="\n'
        '    ;;\n'
        '  *) printf "" ;;\n'
        'esac\n' % (counter, counter))
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert rendered == []
    assert (d / ".pending-tmux").read_text().strip() == "eng1:10-0-0-5"   # kept for later
    assert not (d / "recon" / "tmux-eng1-10-0-0-5.png").exists()
    assert int(counter.read_text().strip()) == 3            # _RENDER_RETRIES honored


def test_drain_pending_tmux_ondisk_verify_keeps_entry_when_png_empty(tmp_path, monkeypatch):
    """Bytes decode fine (>= 100) but the on-disk PNG ends up empty (crashed/truncated
    write) -> treated as NOT rendered: entry stays in .pending-tmux, not counted rendered."""
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    monkeypatch.setattr(ld.os.path, "getsize", lambda p: 0)   # simulate a crashed/empty write
    rendered = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert rendered == []
    assert (d / ".pending-tmux").read_text().strip() == "eng1:10-0-0-5"


def test_loop_driver_main_survives_pending_tmux_marker(vault):
    # a non-empty .pending-tmux marker must not crash/block main() (Area 2 wiring);
    # drain_pending_tmux() itself is unit-tested in isolation above.
    eng = _eng(vault)
    (eng / "oob.md").write_text(OOB_HEADER)
    (eng / ".pending-tmux").write_text("acme:10-0-0-5\n")
    out = _run("loop-driver.py", {"stop_hook_active": False}, _env(vault)).stdout
    assert out.strip() == ""   # pending-tmux alone doesn't force a Stop-gate reason


def test_drain_pending_renders_with_fake_vm(tmp_path):
    import base64
    import importlib.util
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "loop_driver", os.path.join(REPO, "skills", "hooks", "loop-driver.py"))
    ld = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ld)
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap -sV T\n22/tcp open ssh\n")
    # fake vm: a shell that ignores the remote cmd and emits a >=100-byte base64 blob.
    # drain_pending must (a) clear the staged txt, (b) create recon/<name>.png,
    # (c) append a manifest line.
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending(str(d), vm=str(stub))
    assert rendered and rendered[0].endswith(".png")
    assert (d / "recon" / rendered[0]).exists()
    assert not list(pend.glob("*-nmap-*.txt"))     # staged txt consumed
    assert "manifest.md" in os.listdir(str(pend))


def test_drain_pending_retries_transient_render_failure_then_succeeds(tmp_path, monkeypatch):
    """A render that returns < 100 bytes on the first 2 attempts then a valid PNG blob on
    the 3rd must still render the card -- _RENDER_RETRIES bounds the retry loop."""
    import base64
    import subprocess as real_subprocess
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-nmap-abcd1234.txt"
    staged.write_text("# nmap -sV T\n22/tcp open ssh\n")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\necho stub\n")
    os.chmod(str(stub), 0o755)

    good_b64 = base64.b64encode(b"\x00" * 200).decode()
    render_calls = []

    def fake_run(args, **kwargs):
        remote = args[1] if len(args) > 1 else ""
        class _P:
            pass
        p = _P()
        p.returncode = 0
        p.stderr = b""
        if "--term" in remote:
            render_calls.append(remote)
            p.stdout = b"c2hvcnQ=" if len(render_calls) < 3 else good_b64.encode()
        else:
            p.stdout = b""              # one-time shot.py push
        return p

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    rendered = ld.drain_pending(str(d), vm=str(stub))
    assert rendered == ["0001-nmap-abcd1234.png"]
    assert len(render_calls) == 3                    # 2 failures + 1 success
    assert not staged.exists()
    assert (d / "recon" / "0001-nmap-abcd1234.png").exists()


def test_drain_pending_all_retries_fail_leaves_card_staged(tmp_path, monkeypatch):
    """All _RENDER_RETRIES attempts returning < 100 bytes -> the card stays staged
    (fail-open), no PNG, no crash, retried exactly the bound."""
    import subprocess as real_subprocess
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-nmap-abcd1234.txt"
    staged.write_text("# nmap -sV T\n22/tcp open ssh\n")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\necho stub\n")
    os.chmod(str(stub), 0o755)

    render_calls = []

    def fake_run(args, **kwargs):
        remote = args[1] if len(args) > 1 else ""
        class _P:
            pass
        p = _P()
        p.returncode = 0
        p.stderr = b""
        if "--term" in remote:
            render_calls.append(remote)
            p.stdout = b"c2hvcnQ="      # always < 100 bytes decoded
        else:
            p.stdout = b""
        return p

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    rendered = ld.drain_pending(str(d), vm=str(stub))
    assert rendered == []
    assert staged.exists()
    assert len(render_calls) == ld._RENDER_RETRIES
    assert not (d / "recon" / "0001-nmap-abcd1234.png").exists()
    assert "manifest.md" not in os.listdir(str(pend))


def test_drain_pending_ondisk_verify_keeps_card_staged_when_png_empty(tmp_path, monkeypatch):
    """The remote render decodes to >= 100 bytes but the on-disk PNG ends up empty
    (crashed/truncated write) -> treated as NOT rendered: the txt is NOT removed and no
    manifest row is added, so a later drain retries it."""
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-nmap-abcd1234.txt"
    staged.write_text("# nmap -sV T\n22/tcp open ssh\n")
    good_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % good_b64)
    os.chmod(str(stub), 0o755)
    monkeypatch.setattr(ld.os.path, "getsize", lambda p: 0)   # simulate a crashed/empty write
    rendered = ld.drain_pending(str(d), vm=str(stub))
    assert rendered == []
    assert staged.exists()
    assert "manifest.md" not in os.listdir(str(pend))


# ---- Task 3: poc/pages drain wiring (auto page/source capture, Stop drain) ----

def test_loop_driver_drain_poc_pages_fail_open(tmp_path):
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-page-abcd1234.txt"
    staged.write_text(
        "# http://10.0.0.9/login - Login\n$ curl -i http://10.0.0.9/login\n\n<html></html>")
    # no reachable VM -> returns [] without raising, staged txt preserved for a later Stop
    res = ld.drain_pending(str(d), vm="/nonexistent/vm.sh", area="poc/pages")
    assert res == []
    assert staged.exists()


def test_loop_driver_main_spawns_poc_pages_drain(tmp_path, monkeypatch):
    import io
    import subprocess as real_subprocess
    import _engagement
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-page-abcd1234.txt").write_text("# x\n$ x\n\nx")
    (d / "oob.md").write_text(OOB_HEADER)
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(d))
    calls = []

    def fake_popen(args, **kwargs):
        calls.append(args)
        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    monkeypatch.setattr(ld.sys, "stdin", io.StringIO(json.dumps({"stop_hook_active": False})))
    ld.main()
    assert any("poc/pages" in call for call in calls)


# ---- FIX 1 (live-lead-capture): the evidence drain must fire on EVERY Stop, including
# an auto-continue chain (stop_hook_active=true) -- previously the stop_hook_active
# early-return sat BEFORE the drain spawn, so a staged poc/leads/poc/pages/recon card
# never rendered for the rest of a chain.

def test_loop_driver_main_spawns_drain_even_when_stop_hook_active(tmp_path, monkeypatch):
    """Direct proof the drain code path is entered under stop_hook_active=true: the
    Popen call for the poc/leads drain must fire, mirroring
    test_loop_driver_main_spawns_poc_pages_drain but with the chain guard set."""
    import io
    import subprocess as real_subprocess
    import _engagement
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "leads" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-lead-abcd1234.txt").write_text("# curl http://x\n$ curl http://x\n\nflag{x}")
    (d / "oob.md").write_text(OOB_HEADER)
    monkeypatch.setattr(_engagement, "active_dir", lambda: str(d))
    calls = []

    def fake_popen(args, **kwargs):
        calls.append(args)
        class _Dummy:
            pass
        return _Dummy()

    monkeypatch.setattr(real_subprocess, "Popen", fake_popen)
    monkeypatch.setattr(ld.sys, "stdin", io.StringIO(json.dumps({"stop_hook_active": True})))
    ld.main()
    assert any("poc/leads" in call for call in calls)   # drain spawned despite the chain guard


def test_loop_driver_stop_hook_active_drain_fails_open_leaves_lead_staged(vault):
    """Subprocess-level (VM absent in tests): with stop_hook_active=true, an active
    engagement, and a staged poc/leads/.pending/0001-lead-*.txt, main() must still reach
    the drain path. It fails open (no reachable VM) so the .txt stays staged -- exactly
    the fixed live-box gap (the drain used to be skipped entirely during a chain)."""
    eng = _eng(vault)
    (eng / "oob.md").write_text(
        OOB_HEADER + "| tok12345 | http://x/?u= | ssrf | 2026-06-28 | HIT | 1.2.3.4 |\n")
    pend = eng / "poc" / "leads" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-lead-abcd1234.txt"
    staged.write_text("# curl http://x\n$ curl http://x\n\nflag{synthetic}")
    result = _run("loop-driver.py", {"stop_hook_active": True}, _env(vault))
    assert result.returncode == 0
    assert result.stdout.strip() == ""   # reason_for()/print() still gated: no block/reason
    assert staged.exists()               # fail-open (VM absent): .txt left for a later drain


# ---- Task 3: _parse_card_meta (pure helper) + combined browser/stack fail-open ----

def test_parse_card_meta_browser_1_with_url():
    ld = _load_loop_driver()
    lines = ["# cap", "#meta browser=1 url=http://x/", "body line 1", "body line 2"]
    cmd, meta, body_text = ld._parse_card_meta(lines)
    assert cmd == "cap"
    assert meta == {"browser": "1", "url": "http://x/"}
    assert "#meta" not in body_text
    assert body_text == "body line 1\nbody line 2"


def test_parse_card_meta_browser_0_no_url():
    ld = _load_loop_driver()
    lines = ["# cap", "#meta browser=0", "body"]
    cmd, meta, body_text = ld._parse_card_meta(lines)
    assert cmd == "cap"
    assert meta.get("browser") == "0"
    assert "url" not in meta
    assert "#meta" not in body_text
    assert body_text == "body"


def test_parse_card_meta_no_meta_line_matches_todays_parse():
    """A recon/leads-style card (# cmd + body, no #meta line): meta=={}, and body_text
    equals today's plain "\\n".join(lines[1:]) parse -- equivalence with the pre-Task-3
    recon/poc-leads behavior."""
    ld = _load_loop_driver()
    lines = ["# nmap -sV T", "22/tcp open ssh", "80/tcp open http"]
    cmd, meta, body_text = ld._parse_card_meta(lines)
    assert cmd == "nmap -sV T"
    assert meta == {}
    assert body_text == "\n".join(lines[1:])


def test_parse_card_meta_line0_not_hash():
    ld = _load_loop_driver()
    lines = ["not a comment", "body"]
    cmd, meta, body_text = ld._parse_card_meta(lines)
    assert cmd is None
    assert meta == {}
    assert body_text == "\n".join(lines)


def test_parse_card_meta_never_raises_on_empty_or_single_line():
    ld = _load_loop_driver()
    cmd, meta, body_text = ld._parse_card_meta([])
    assert cmd is None
    assert meta == {}
    assert body_text == ""
    cmd, meta, body_text = ld._parse_card_meta(["# only"])
    assert cmd == "only"
    assert meta == {}
    assert body_text == ""


def test_loop_driver_drain_poc_pages_browser_1_fail_open(tmp_path):
    """Mirrors test_loop_driver_drain_poc_pages_fail_open but the staged card carries the
    Task-1 browser=1 metadata line. With no reachable VM, the combined browser+stack path
    must never be attempted -- drain_pending still fails open: returns [] and leaves the
    .txt staged for a later Stop, no exception."""
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-page-abcd1234.txt"
    staged.write_text(
        "# http://10.0.0.9/login - Login\n#meta browser=1 url=http://10.0.0.9/login\n"
        "$ curl -i http://10.0.0.9/login\n\n<html></html>")
    res = ld.drain_pending(str(d), vm="/nonexistent/vm.sh", area="poc/pages")
    assert res == []
    assert staged.exists()


# ---- Task 2: colored + widened poc/pages term card, clean-refetch combined bottom ----

def test_drain_cli_dispatch_poc_pages_predicate_includes_reqresp(tmp_path):
    """__main__ --drain dispatch change (a): area=poc/pages must now thread reqresp=True
    into drain_pending, same as poc/leads -- the remote render command must carry
    --reqresp --maxlines 600 (previously only poc/leads got this)."""
    import base64
    import sys
    ld_path = os.path.join(REPO, "skills", "hooks", "loop-driver.py")
    d = tmp_path / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-page-abcd1234.txt").write_text(
        "# http://x/login - Login\n$ curl -i http://x/login\n\n<html></html>")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    captured = tmp_path / "captured.txt"
    stub = tmp_path / "fakevm.sh"
    stub.write_text(
        '#!/bin/bash\n'
        'echo "$1" >> "%s"\n'
        'printf "%%s" "%s"\n' % (captured, big_b64))
    os.chmod(str(stub), 0o755)
    result = subprocess.run(
        [sys.executable, ld_path, "--drain", str(d), "poc/pages"],
        capture_output=True, text=True,
        env={**os.environ, "VM_SH": str(stub)},
        timeout=30)
    assert result.returncode == 0
    assert (d / "poc" / "pages" / "0001-page-abcd1234.png").exists()
    assert "--reqresp --maxlines 600" in captured.read_text()


def test_drain_cli_dispatch_recon_predicate_excludes_reqresp(tmp_path):
    """recon area must still NOT get --reqresp (unchanged by Task 2)."""
    import base64
    import sys
    ld_path = os.path.join(REPO, "skills", "hooks", "loop-driver.py")
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap -sV T\n22/tcp open ssh\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    captured = tmp_path / "captured.txt"
    stub = tmp_path / "fakevm.sh"
    stub.write_text(
        '#!/bin/bash\n'
        'echo "$1" >> "%s"\n'
        'printf "%%s" "%s"\n' % (captured, big_b64))
    os.chmod(str(stub), 0o755)
    result = subprocess.run(
        [sys.executable, ld_path, "--drain", str(d), "recon"],
        capture_output=True, text=True,
        env={**os.environ, "VM_SH": str(stub)},
        timeout=30)
    assert result.returncode == 0
    assert (d / "recon" / "0001-nmap-abcd1234.png").exists()
    assert "--reqresp" not in captured.read_text()


def test_drain_pending_combined_bottom_is_clean_fetch_not_staged_body(tmp_path, monkeypatch):
    """Task 2 change (b): the BOTTOM (term) card of a browser=1 combined poc/pages card
    must be rendered from a FRESH clean re-fetch of the URL (curl -sSi <url>), never the
    raw staged body -- proven by recording every remote command issued and the bytes that
    end up in the written PNG. The top browser render here returns non-image bytes, so
    stack_vertical fails closed (PIL cannot open it) and the combined path falls back to
    the plain bottom card per the reviewed fail-open contract -- which must still be the
    CLEAN fetch, not the staged body. Live chromium/curl behavior is validated on-box."""
    import base64
    import subprocess as real_subprocess
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-page-abcd1234.txt"
    staged.write_text(
        "# http://10.0.0.9/login - Login\n#meta browser=1 url=http://10.0.0.9/login\n"
        "$ curl -i http://10.0.0.9/login\n\nSTAGED-BODY-MUST-NOT-BE-USED")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\necho stub\n")
    os.chmod(str(stub), 0o755)

    clean_marker = b"CLEAN-FETCH-BYTES-" + b"X" * 100
    clean_b64 = base64.b64encode(clean_marker).decode()
    top_b64 = base64.b64encode(b"\x00" * 200).decode()   # not a real PNG -> stack fails closed

    calls = []

    def fake_run(args, **kwargs):
        remote = args[1] if len(args) > 1 else ""
        calls.append(remote)
        class _P:
            pass
        p = _P()
        p.returncode = 0
        p.stderr = b""
        if "curl -sSi" in remote:
            p.stdout = clean_b64.encode()
        elif "-top.png" in remote:
            p.stdout = top_b64.encode()
        elif "base64 -d" in remote:            # staged-body fallback -- must never fire here
            p.stdout = b"SHOULD-NOT-BE-CALLED-" + b"Y" * 100
        else:
            p.stdout = b""                     # shot.py push
        return p

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    rendered = ld.drain_pending(str(d), vm=str(stub), area="poc/pages")
    assert rendered == ["0001-page-abcd1234.png"]
    png_bytes = (d / "poc" / "pages" / "0001-page-abcd1234.png").read_bytes()
    assert png_bytes == clean_marker
    assert any("curl -sSi" in c and "10.0.0.9/login" in c and "--reqresp --maxlines 600" in c
               for c in calls)
    # discriminate the staged-body fallback render (target /tmp/poc/<stem>.txt) from the
    # one-time shot.py push (target /tmp/shot.py), which also contains "base64 -d"
    assert not any("base64 -d > /tmp/poc/" in c for c in calls)   # fallback never triggered


def test_drain_pending_combined_clean_fetch_failure_falls_back_to_staged_body(tmp_path, monkeypatch):
    """FAIL-OPEN: if the clean re-fetch yields < 100 bytes (curl failed / URL unreachable),
    the bottom card falls back to rendering the STAGED body exactly as before Task 2."""
    import base64
    import subprocess as real_subprocess
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-page-abcd1234.txt"
    staged.write_text(
        "# http://10.0.0.9/login - Login\n#meta browser=1 url=http://10.0.0.9/login\n"
        "$ curl -i http://10.0.0.9/login\n\nSTAGED-BODY-FALLBACK")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\necho stub\n")
    os.chmod(str(stub), 0o755)

    fallback_marker = b"STAGED-FALLBACK-BYTES-" + b"Z" * 100
    fallback_b64 = base64.b64encode(fallback_marker).decode()

    calls = []

    def fake_run(args, **kwargs):
        remote = args[1] if len(args) > 1 else ""
        calls.append(remote)
        class _P:
            pass
        p = _P()
        p.returncode = 0
        p.stderr = b""
        if "curl -sSi" in remote:
            p.stdout = b"c2hvcnQ="                  # base64("short") -> < 100 bytes decoded
        elif "base64 -d" in remote:                  # staged-body fallback path
            p.stdout = fallback_b64.encode()
        elif "-top.png" in remote:
            p.stdout = b""                           # top render fails too; irrelevant here
        else:
            p.stdout = b""                           # shot.py push
        return p

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    rendered = ld.drain_pending(str(d), vm=str(stub), area="poc/pages")
    assert rendered == ["0001-page-abcd1234.png"]
    png_bytes = (d / "poc" / "pages" / "0001-page-abcd1234.png").read_bytes()
    assert png_bytes == fallback_marker
    assert any("curl -sSi" in c for c in calls)        # clean fetch was attempted first
    assert any("base64 -d > /tmp/poc/" in c for c in calls)   # then fell back to the staged body


def test_drain_pending_combined_both_renders_fail_keeps_card_staged(tmp_path, monkeypatch):
    """If BOTH the clean fetch and the staged-body fallback render fail (< 100 bytes), the
    card is kept staged for a later Stop -- same as today's plain term-render failure."""
    import subprocess as real_subprocess
    ld = _load_loop_driver()
    d = tmp_path / "targets" / "ENG"
    pend = d / "poc" / "pages" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-page-abcd1234.txt"
    staged.write_text(
        "# http://10.0.0.9/login - Login\n#meta browser=1 url=http://10.0.0.9/login\n"
        "$ curl -i http://10.0.0.9/login\n\nbody")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\necho stub\n")
    os.chmod(str(stub), 0o755)

    def fake_run(args, **kwargs):
        class _P:
            pass
        p = _P()
        p.returncode = 0
        p.stderr = b""
        p.stdout = b"c2hvcnQ="       # base64("short") -> always < 100 bytes decoded
        return p

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    rendered = ld.drain_pending(str(d), vm=str(stub), area="poc/pages")
    assert rendered == []
    assert staged.exists()
    assert not (d / "poc" / "pages" / "0001-page-abcd1234.png").exists()


# ---- drainkick: per-area render lock (_try_lock/_unlock) + drain wiring ----

def test_try_lock_free_path_acquires_and_creates_file(tmp_path):
    ld = _load_loop_driver()
    lockpath = str(tmp_path / ".draining")
    assert ld._try_lock(lockpath) is True
    assert os.path.isfile(lockpath)


def test_try_lock_fresh_lock_held_returns_false(tmp_path):
    ld = _load_loop_driver()
    lockpath = str(tmp_path / ".draining")
    assert ld._try_lock(lockpath) is True
    assert ld._try_lock(lockpath) is False   # fresh lock still held by "another drain"


def test_try_lock_stale_lock_is_reclaimed(tmp_path):
    ld = _load_loop_driver()
    lockpath = tmp_path / ".draining"
    lockpath.write_text("12345")
    old = os.path.getmtime(str(lockpath)) - 700   # > default stale=600
    os.utime(str(lockpath), (old, old))
    assert ld._try_lock(str(lockpath)) is True
    assert lockpath.exists()   # reclaimed with a fresh lock (not just removed)


def test_try_lock_slow_but_live_lock_not_reclaimed_under_raised_window(tmp_path):
    """A lock aged ~300s (older than the pre-fix stale=180 window, but well under the
    new stale=600 window) must NOT be reclaimed: this is exactly the "legitimately-alive
    but slow render" case the widened window + heartbeat exist to protect. Proves the
    fix raised the window rather than merely renaming it."""
    ld = _load_loop_driver()
    lockpath = tmp_path / ".draining"
    lockpath.write_text("12345")
    old = os.path.getmtime(str(lockpath)) - 300   # between old (180) and new (600) windows
    os.utime(str(lockpath), (old, old))
    assert ld._try_lock(str(lockpath)) is False   # still fresh under the new window -> not reclaimed
    assert lockpath.exists()


def test_try_lock_past_600s_is_reclaimed(tmp_path):
    """A lock aged just past the new 600s window is reclaimed (the genuinely-crashed-drain
    case still works after the window was raised)."""
    ld = _load_loop_driver()
    lockpath = tmp_path / ".draining"
    lockpath.write_text("12345")
    old = os.path.getmtime(str(lockpath)) - 601
    os.utime(str(lockpath), (old, old))
    assert ld._try_lock(str(lockpath)) is True
    assert lockpath.exists()


def test_unlock_removes_file(tmp_path):
    ld = _load_loop_driver()
    lockpath = tmp_path / ".draining"
    lockpath.write_text("1")
    ld._unlock(str(lockpath))
    assert not lockpath.exists()


def test_try_lock_unwritable_path_never_blocks(tmp_path):
    ld = _load_loop_driver()
    # a path whose parent directory does not exist -> os.open raises, never FileExistsError
    bogus = str(tmp_path / "does" / "not" / "exist" / ".draining")
    assert ld._try_lock(bogus) is True   # fail-open: never block rendering on a lock problem


def test_unlock_never_raises_on_missing_file(tmp_path):
    ld = _load_loop_driver()
    ld._unlock(str(tmp_path / "nope" / ".draining"))   # must not raise


def test_drain_pending_short_circuits_on_fresh_lock(tmp_path):
    """A FRESH .draining lock pre-created in the .pending dir must prevent drain_pending
    from rendering at all -- even with a REACHABLE vm that would otherwise render fine.
    Proves the lock is actually checked (not just present-but-ignored) and that it is
    checked before/instead of doing any rendering work."""
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    staged = pend / "0001-nmap-abcd1234.txt"
    staged.write_text("# nmap -sV T\n22/tcp open ssh\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    lockpath = pend / ".draining"
    lockpath.write_text("99999")   # fresh (just created) -> held by "another drain"
    res = ld.drain_pending(str(d), vm=str(stub))
    assert res == []
    assert lockpath.exists()   # short-circuit: lock left untouched (never released by the loser)
    assert staged.exists()     # nothing rendered/consumed despite a reachable VM


def test_drain_pending_releases_lock_after_normal_run(tmp_path):
    """Existing render-with-fake-vm behavior stays intact, AND the .draining lock created
    during the attempt is cleaned up afterward (finally ran) -- no leftover lockfile."""
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap -sV T\n22/tcp open ssh\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending(str(d), vm=str(stub))
    assert rendered and rendered[0].endswith(".png")   # unchanged rendering behavior
    assert not (pend / ".draining").exists()           # lock released (finally ran)


def test_drain_pending_vm_absent_still_releases_lock(tmp_path):
    """Keep the existing VM-absent fail-open assertions green, AND assert the .draining
    lock never leaks even on the VM-absent early-return path (inside the try/finally)."""
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap -sV T\n22/tcp open ssh\n")
    res = ld.drain_pending(str(d), vm="/nonexistent/vm.sh")
    assert res == []                                    # unchanged fail-open behavior
    assert (pend / "0001-nmap-abcd1234.txt").exists()    # staged txt untouched (VM absent)
    assert not (pend / ".draining").exists()             # lock released (finally ran)


def test_drain_pending_heartbeats_lock_during_render(tmp_path, monkeypatch):
    """The Important defect this guards: a per-card render can run long enough to cross
    the OLD 180s stale window. drain_pending must touch (heartbeat) the lock's mtime at
    the top of every per-item loop iteration so a live drain never looks stale to a
    second kick's _try_lock. Proven causally: backdate the lock's mtime right after
    acquisition (before the render loop starts), then observe via a stubbed
    subprocess.run that the mtime seen by the per-card render call (the 2nd subprocess
    call; the 1st pushes shot.py) has already been refreshed by the heartbeat."""
    import base64
    import subprocess as real_subprocess
    import time
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    pend = d / "recon" / ".pending"
    pend.mkdir(parents=True)
    (pend / "0001-nmap-abcd1234.txt").write_text("# nmap -sV T\n22/tcp open ssh\n")
    stub = tmp_path / "fakevm.sh"
    stub.write_text("#!/bin/bash\necho stub\n")
    os.chmod(str(stub), 0o755)

    lock = pend / ".draining"
    old_time = time.time() - 300   # older than the render loop start
    real_try_lock = ld._try_lock

    def backdating_try_lock(lockpath, *a, **kw):
        ok = real_try_lock(lockpath, *a, **kw)
        if ok and os.path.isfile(lockpath):
            os.utime(lockpath, (old_time, old_time))   # simulate a lock acquired a while ago
        return ok

    monkeypatch.setattr(ld, "_try_lock", backdating_try_lock)

    seen_mtimes = []
    big_b64 = base64.b64encode(b"\x00" * 200).decode()

    def fake_run(args, **kwargs):
        if lock.exists():
            seen_mtimes.append(os.path.getmtime(str(lock)))
        class _P:
            pass
        p = _P()
        p.stdout = big_b64.encode()
        p.stderr = b""
        p.returncode = 0
        return p

    monkeypatch.setattr(real_subprocess, "run", fake_run)
    rendered = ld.drain_pending(str(d), vm=str(stub))
    assert rendered and rendered[0].endswith(".png")   # render proceeded (sanity)
    assert len(seen_mtimes) >= 2
    assert abs(seen_mtimes[0] - old_time) < 2                 # shot.py push: before the heartbeat
    assert seen_mtimes[1] > old_time + 100                    # per-card render: heartbeat already ran


def test_drain_pending_tmux_short_circuits_on_fresh_lock(tmp_path):
    """Same short-circuit proof for the tmux drain, using a reachable fake vm."""
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    lockpath = d / ".draining-tmux"
    lockpath.write_text("99999")
    res = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert res == []
    assert lockpath.exists()
    assert (d / ".pending-tmux").read_text().strip() == "eng1:10-0-0-5"   # nothing consumed


def test_drain_pending_tmux_releases_lock_after_normal_run(tmp_path):
    import base64
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    big_b64 = base64.b64encode(b"\x00" * 200).decode()
    stub = tmp_path / "fakevm.sh"
    stub.write_text('#!/bin/bash\nprintf "%%s" "%s"\n' % big_b64)
    os.chmod(str(stub), 0o755)
    rendered = ld.drain_pending_tmux(str(d), vm=str(stub))
    assert rendered == ["tmux-eng1-10-0-0-5.png"]
    assert not (d / ".draining-tmux").exists()   # lock released (finally ran)


def test_drain_pending_tmux_vm_absent_still_releases_lock(tmp_path):
    ld = _load_loop_driver()
    d = tmp_path / "ENG"
    d.mkdir()
    (d / ".pending-tmux").write_text("eng1:10-0-0-5\n")
    res = ld.drain_pending_tmux(str(d), vm="/nonexistent/vm.sh")
    assert res == []                                          # existing fail-open behavior
    assert (d / ".pending-tmux").read_text().strip() == "eng1:10-0-0-5"
    assert not (d / ".draining-tmux").exists()                # lock released (finally ran)


# ---- SOLVED-suppression: a solved engagement runs ONLY the walkthrough/learn close-out
#      gates; leftover active-hunt markers (wiki / capture / coverage / evidence) never nag ----


def test_loop_driver_never_blocks(vault):
    eng = _eng(vault)
    # stale enforcement markers that USED to force a block must no longer do so
    (eng / ".pending-tests").write_text(json.dumps(["sqli", "auth"]))
    (eng / ".pending-evidence").write_text(json.dumps(
        [{"value": "flag", "context": "", "poc_count": 0, "ts": 9999999999}]))
    (eng / ".pending-capture").write_text(json.dumps(
        {"tool": "nmap", "state_rows": 9, "loot_rows": 9}))
    out = _run("loop-driver.py", {"stop_hook_active": False}, _env(vault)).stdout
    assert '"decision"' not in out          # never blocks / forces continuation
    assert "fingerprinted" not in out
    assert out.strip() == ""                 # render-only drain: no block output


def test_loop_driver_has_no_gate_machinery():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ld", os.path.join(HOOKS, "loop-driver.py"))
    ld = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ld)
    assert not hasattr(ld, "reason_for")
    assert not hasattr(ld, "_read_budget")
    assert hasattr(ld, "drain_pending")      # the capture drain stays
