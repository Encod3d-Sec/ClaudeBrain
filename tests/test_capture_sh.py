"""capture.sh mode dispatch (bash). Offline: these paths exit at arg-check before any vm.sh call."""
import subprocess
import pathlib

CAP = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "capture.sh"


def _run(*args, env=None):
    return subprocess.run(["bash", str(CAP), *args], capture_output=True, text=True, env=env)


def test_web_is_a_known_mode():
    # too few args -> the web usage line, proving mode_web is dispatched (not "unknown mode")
    r = _run("web", "eng")  # 2 args, web needs >=3
    assert r.returncode == 2
    assert "capture.sh web <eng> <slug> <url>" in r.stderr
    assert "unknown mode" not in r.stderr


def test_help_lists_web():
    r = _run("--help")
    assert "web  <eng> <slug> <url>" in r.stderr


def test_help_documents_source_card_pairing():
    r = _run("--help")
    assert "-source.md" in r.stderr, "usage must document that every capture writes a source card"


def test_recon_is_a_known_mode():
    # too few args -> the recon usage line, proving mode_recon is dispatched (not "unknown mode")
    r = _run("recon", "eng", "slug")  # 2 args reach mode_recon, which needs >=3
    assert r.returncode == 2
    assert "capture.sh recon <eng> <slug> <tmux-tab>" in r.stderr
    assert "unknown mode" not in r.stderr


def test_help_lists_recon():
    r = _run("--help")
    assert "recon <eng> <slug> <tmux-tab>" in r.stderr


def test_log_is_a_known_mode():
    # too few args -> the log usage line, proving mode_log is dispatched (not "unknown mode")
    r = _run("log", "eng", "slug")  # 2 args reach mode_log, which needs >=3
    assert r.returncode == 2
    assert "capture.sh log <eng> <slug> <remote-logfile>" in r.stderr
    assert "unknown mode" not in r.stderr


def test_help_lists_log():
    r = _run("--help")
    assert "log  <eng> <slug> <remote-logfile>" in r.stderr


def test_snippet_is_a_known_mode():
    # 2 args reach mode_snippet, which needs >=3 -> its usage line (not "unknown mode")
    r = _run("snippet", "eng", "slug")
    assert r.returncode == 2
    assert "capture.sh snippet <eng> <slug> <url-or-file>" in r.stderr
    assert "unknown mode" not in r.stderr


def test_help_lists_snippet():
    r = _run("--help")
    assert "snippet <eng> <slug> <url-or-file>" in r.stderr


def test_snippet_extracts_filtered_lines_from_a_local_file(tmp_path):
    # functional: a local source file + a grep pattern -> a fenced .md holding only the matched
    # lines (with source line numbers) and the reveals note. VAULT is overridden to a tmp dir so
    # the poc/ write does not touch the real vault.
    import os
    src = tmp_path / "app.js"
    src.write_text(
        "const x = 1;\n"
        "  res = await fetch('/api/move', { method: 'POST' });\n"
        "const y = 2;\n"
        "  const res = await fetch('/api/settings', { method: 'POST' });\n"
    )
    env = dict(os.environ, VAULT=str(tmp_path), VM_SH="/bin/false")
    r = _run("snippet", "eng1", "api-map", str(src), "fetch\\('/api", "the API endpoints", env=env)
    assert r.returncode == 0, r.stderr
    md = tmp_path / "targets" / "eng1" / "poc" / "01-api-map-snippet.md"
    assert md.exists()
    body = md.read_text()
    assert "```js" in body                      # lang guessed from .js
    assert "/api/move" in body and "/api/settings" in body
    assert "const x = 1" not in body            # non-matching line filtered out
    assert "2:" in body and "4:" in body        # source line numbers preserved
    assert "_reveals: the API endpoints_" in body


def test_snippet_rejects_a_nonmatching_pattern(tmp_path):
    import os
    src = tmp_path / "app.js"
    src.write_text("nothing interesting here\n")
    env = dict(os.environ, VAULT=str(tmp_path), VM_SH="/bin/false")
    r = _run("snippet", "eng1", "s", str(src), "NOPE_NO_MATCH", env=env)
    assert r.returncode == 1
    assert "matched nothing" in r.stderr


def test_unknown_mode_still_rejected():
    r = _run("bogus")
    assert r.returncode == 2
    assert "unknown mode" in r.stderr


def test_burp_mode_selects_created_tab_by_oracle():
    # burpshot must SELECT the tab it created (create_repeater_tab appends but does not focus it) and
    # VERIFY via the active-editor oracle before Send/grab -- never a stale-tab PoC. Source-level check
    # because the live Burp GUI path cannot run in CI.
    src = CAP.read_text()
    assert "get_active_editor_contents" in src   # the oracle that confirms which tab is focused
    assert "ctrl+equal" in src                    # go_to_next_tab navigation to reach the created tab
    assert "could not select" in src              # fail-loud when the intended tab cannot be confirmed


def test_recon_sanitizes_the_session_name(tmp_path):
    # capture.sh must address the SAME session name vm-scan.sh created, or the card silently
    # fails. A stub vm.sh echoes the remote command so the target string can be asserted.
    import os
    # mode_recon base64s $VAULT/scripts/shot.py before it ever reaches vm.sh, so it must exist
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "shot.py").write_text("# stub\n")
    stub = tmp_path / "vm.sh"
    stub.write_text('#!/usr/bin/env bash\necho "$1" >&2\n')
    stub.chmod(0o755)
    env = dict(os.environ, VAULT=str(tmp_path), VM_SH=str(stub))
    r = _run("recon", "eng1", "ffuf", "ffuf-web1", "prog1/app.example.com", env=env)
    # the pull produces no PNG so it exits 1; what matters is the target it addressed
    assert "prog1-app-example-com:ffuf-web1" in r.stderr


def test_raw_pulls_a_remote_file_into_a_fenced_md(tmp_path):
    # a stub vm.sh prints base64 of a fixture, exercising the real pull path with no VM.
    # Output is .md (Obsidian only previews .md) with the payload preserved verbatim in a fence.
    import json
    import os
    fixture = tmp_path / "src.json"
    fixture.write_text('{"results":[{"url":"http://h/.env","status":200}]}')
    stub = tmp_path / "vm.sh"
    stub.write_text('#!/usr/bin/env bash\nbase64 -w0 "%s"\n' % fixture)
    stub.chmod(0o755)
    env = dict(os.environ, VAULT=str(tmp_path), VM_SH=str(stub))
    r = _run("raw", "eng1", "ffuf.json", "/tmp/scans/web1/ffuf.json", env=env)
    assert r.returncode == 0, r.stderr
    dest = tmp_path / "targets" / "eng1" / "recon" / "raw" / "ffuf.md"
    assert dest.exists()
    body = dest.read_text()
    assert "```json" in body                      # fence language from the extension
    assert "/tmp/scans/web1/ffuf.json" in body    # provenance recorded
    # payload survives verbatim, so it still parses once the fence is stripped
    inner = body.split("```json\n", 1)[1].rsplit("\n```", 1)[0]
    assert json.loads(inner)["results"][0]["url"] == "http://h/.env"
