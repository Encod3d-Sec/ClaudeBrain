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


def test_suppresses_scan_when_output_shows_cloudflare(vault):
    _scope(vault)
    r = _run(_payload("curl -I https://10.0.0.5/",
                      "HTTP/2 200\nserver: cloudflare\ncf-ray: a258e1f1ffe2c9d5-VNO"), vault)
    assert "AUTO WEB-RECON" not in r.stdout
    assert "CLOUDFLARE" in r.stdout
    assert "http://10.0.0.5" in _ledger(vault) or "https://10.0.0.5" in _ledger(vault)


def test_cf_ledger_entry_prevents_a_later_rescan(vault):
    _scope(vault)
    _run(_payload("curl -I https://10.0.0.5/", "HTTP/2 200\nserver: cloudflare"), vault)
    r2 = _run(_payload("curl -I https://10.0.0.5/", "HTTP/2 200\nserver: nginx"), vault)
    assert "AUTO WEB-RECON" not in r2.stdout


def test_force_env_overrides_the_cf_gate(vault):
    _scope(vault)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault),
               WEB_RECON_DRYRUN="1", WEB_RECON_FORCE="1")
    r = subprocess.run(["python3", HOOK],
                       input=json.dumps(_payload("curl -I https://10.0.0.5/",
                                                 "HTTP/2 200\nserver: cloudflare")),
                       capture_output=True, text=True, env=env, timeout=20)
    assert "AUTO WEB-RECON" in r.stdout


def test_non_cloudflare_server_header_still_launches(vault):
    _scope(vault)
    r = _run(_payload("curl -I https://10.0.0.5/", "HTTP/2 200\nserver: nginx/1.24"), vault)
    assert "AUTO WEB-RECON" in r.stdout


def test_multi_host_blob_evidence_is_not_cross_attributed(vault):
    # One command's output covers TWO distinct in-scope hosts (e.g. a multi-target curl/httpx
    # run): host a is Cloudflare-fronted, host b is plain nginx. A's header must not leak
    # into b's verdict (over-suppression) and b's header must not leak into a's (a false
    # "clear" that would let a scanner hit the CF-fronted host).
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- a.acme.internal\n- b.acme.internal\n\n## Out of scope\n- 10.0.0.1\n",
        encoding="utf-8")
    cmd = "curl -I https://a.acme.internal/ ; curl -I https://b.acme.internal/"
    out = (
        "https://a.acme.internal/\n"
        "HTTP/2 200\n"
        "server: cloudflare\n"
        "cf-ray: a258e1f1ffe2c9d5-VNO\n"
        "\n"
        "https://b.acme.internal/\n"
        "HTTP/2 200\n"
        "server: nginx\n"
    )
    r = _run(_payload(cmd, out), vault)
    assert "CLOUDFLARE detected" in r.stdout
    assert "AUTO WEB-RECON" in r.stdout
    ledger = _ledger(vault)
    assert "a.acme.internal" in ledger
    assert "b.acme.internal" in ledger


def test_single_host_no_literal_blob_still_launches(vault):
    # Companion to the multi-host bypass test below: a SINGLE in-scope host, plain `curl -sI`
    # output that carries no URL literal and no server evidence at all. This is exactly the
    # shape all six pre-existing tests already use (a single surface per invocation), and it
    # must keep launching under "unknown" -- the multi-host attribution fix must not make a
    # single-surface invocation any more conservative than it already was.
    _scope(vault)
    r = _run(_payload("curl -sI https://10.0.0.5/", "HTTP/2 200\ndate: Mon\n"), vault)
    assert "AUTO WEB-RECON" in r.stdout
    assert "https://10.0.0.5" in _ledger(vault)


def test_multi_host_no_literal_blob_does_not_launch_either_host(vault):
    # The reviewer's exact bypass reproduction: TWO in-scope hosts probed by a chained plain
    # `curl -sI a ; curl -sI b`, neither of which echoes its own URL into stdout. The blob's
    # only header evidence (`server: nginx`) cannot be attributed to either host. Neither may
    # launch: not the "plain" one (we don't actually know that) and certainly not the one that
    # may be Cloudflare-fronted. This must fail against the pre-fix _cf_verdict, which searched
    # the whole blob regardless of host and would have returned "clear" for both, launching
    # scanners straight at a possibly-Cloudflare-fronted target.
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- cf.acme.internal\n- plain.acme.internal\n\n## Out of scope\n- 10.0.0.1\n",
        encoding="utf-8")
    cmd = "curl -sI https://cf.acme.internal/ ; curl -sI https://plain.acme.internal/"
    out = "HTTP/2 200\ndate: Mon\n\nHTTP/2 200\nserver: nginx\n"
    r = _run(_payload(cmd, out), vault)
    assert "AUTO WEB-RECON" not in r.stdout
    ledger = _ledger(vault)
    assert "cf.acme.internal" not in ledger
    assert "plain.acme.internal" not in ledger


def test_port_variants_of_same_host_are_distinct_surfaces(vault):
    # Round-2 re-review's bypass: TWO genuinely different surfaces sharing a hostname but
    # differing only by port (probing an alternate origin port while the edge fronts :443
    # is a standard Cloudflare-bypass recon technique) must not collapse into a false
    # singleton just because _host() strips the port. Only one leg answered with real
    # (unattributable) headers; the :443 (presumed Cloudflare-fronted) surface must not
    # inherit a "clear" verdict from the shared blob. This must fail against the pre-fix
    # host-keyed (not authority-keyed) hosts_in_play, which collapses both URLs to the
    # single host "cf.acme.internal" and trusts the whole blob unconditionally for both.
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- cf.acme.internal\n\n## Out of scope\n- 10.0.0.1\n",
        encoding="utf-8")
    cmd = "curl -sI https://cf.acme.internal:8080/ ; curl -sI https://cf.acme.internal:443/"
    out = "HTTP/1.1 200 OK\nserver: nginx\n"
    r = _run(_payload(cmd, out), vault)
    assert "AUTO WEB-RECON" not in r.stdout
    ledger = _ledger(vault)
    assert "cf.acme.internal:443" not in ledger
    assert "cf.acme.internal:8080" not in ledger
