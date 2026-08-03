import json
import os
import subprocess

import _engagement  # noqa: F401  self-locate before the vault fixture (mirrors test_hooks.py)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "skills", "hooks", "web-recon.py")


def _scope(vault):
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- 10.0.0.5\n\n## Out of scope\n- 10.0.0.1\n", encoding="utf-8")


def _payload(cmd, out):
    return {"tool_name": "Bash", "tool_input": {"command": cmd},
            "tool_response": {"stdout": out}}


def _run(payload, vault):
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault), WEB_RECON_DRYRUN="1")
    return subprocess.run(["python3", HOOK], input=json.dumps(payload),
                          capture_output=True, text=True, env=env, timeout=20)


def _ledger(vault):
    p = vault / "targets" / "acme" / ".web-surfaces"
    return p.read_text() if p.exists() else ""


def test_launches_on_inscope_open_http(vault):
    _scope(vault)
    r = _run(_payload("nmap -sV 10.0.0.5", "80/tcp open http"), vault)
    assert "AUTO WEB-RECON" in r.stdout
    assert "http://10.0.0.5:80" in _ledger(vault)


def test_skips_out_of_scope(vault):
    _scope(vault)
    r = _run(_payload("nmap -sV 10.0.0.1", "80/tcp open http"), vault)
    assert "AUTO WEB-RECON" not in r.stdout
    assert "10.0.0.1" not in _ledger(vault)


def test_launches_on_inscope_redirect_vhost(vault):
    _scope(vault)
    r = _run(_payload("curl -I http://10.0.0.5/", "HTTP/1.1 302 Found\nLocation: http://shop.acme/app/"), vault)
    assert "AUTO WEB-RECON" in r.stdout
    assert "http://shop.acme" in _ledger(vault)


def test_idempotent(vault):
    _scope(vault)
    _run(_payload("nmap 10.0.0.5", "80/tcp open http"), vault)
    r2 = _run(_payload("nmap 10.0.0.5", "80/tcp open http"), vault)
    assert "AUTO WEB-RECON" not in r2.stdout
    assert _ledger(vault).count("http://10.0.0.5:80") == 1


def test_framework_meta_skipped(vault):
    _scope(vault)
    r = _run(_payload("cat scripts/playbook.json", "80/tcp open http http://10.0.0.5"), vault)
    assert "AUTO WEB-RECON" not in r.stdout


def test_fail_open_on_garbage(vault):
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault), WEB_RECON_DRYRUN="1")
    r = subprocess.run(["python3", HOOK], input="garbage", capture_output=True,
                       text=True, env=env, timeout=20)
    assert r.returncode == 0
