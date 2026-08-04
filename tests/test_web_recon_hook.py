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


def _canon(url):
    """The canonical surface identity restated independently from the requirement
    (scheme + host + port, default port made explicit) rather than imported from the hook,
    so the matrix below asserts against the spec and not against whatever the hook
    currently computes."""
    scheme, _, rest = url.partition("://")
    host, _, port = rest.partition(":")
    return "%s://%s:%s" % (scheme, host, port or ("443" if scheme == "https" else "80"))


# Every spelling of one real surface, plus a second genuinely distinct host. Rows 1-3 and
# 4-6 each name ONE real surface twice (omitted vs explicit default port) and one truly
# different one (non-default port); rows 1-3 vs 4-6 differ by scheme, which is a different
# real surface (plaintext :80 vs the TLS/CDN edge on :443).
_SURFACE_VARIANTS = [
    "http://cf.acme.internal",        # http,  port omitted        -> :80
    "http://cf.acme.internal:80",     # http,  explicit default    -> :80
    "http://cf.acme.internal:8080",   # http,  non-default port
    "https://cf.acme.internal",       # https, port omitted        -> :443
    "https://cf.acme.internal:443",   # https, explicit default    -> :443
    "https://cf.acme.internal:8443",  # https, non-default port
    "https://plain.acme.internal",    # a second, distinct host
]


def test_surface_variant_matrix_never_launches_on_foreign_evidence(vault):
    # The CLASS test, not a fourth pairwise repro. Every one of the previous bypasses was
    # the same defect: an attribution identity built by stripping components by hand
    # (hostname, then port, then scheme), so two genuinely different real surfaces
    # collapsed into one string and the whole shared output blob was trusted for both.
    # This enumerates the full variant matrix -- scheme x (omitted / explicit default /
    # non-default port) x a second host -- and pins BOTH halves of the canonical identity
    # at once, so no single axis can be point-patched into passing:
    #   different real surfaces  -> the shared header may decide NOTHING for either
    #                               (never launch a possibly-Cloudflare-fronted surface on
    #                               evidence that belongs to a different one)
    #   same real surface twice  -> must NOT fragment into a phantom multi-surface hold
    # The blob is the shape that matters in production: chained plain `curl -sI`, which
    # never echoes its own request URL, with exactly one leg answering.
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- cf.acme.internal\n- plain.acme.internal\n\n## Out of scope\n- 10.0.0.1\n",
        encoding="utf-8")
    ledger = vault / "targets" / "acme" / ".web-surfaces"
    # Collect every violation instead of failing on the first, so a broken identity
    # function reports the whole shape of what it got wrong, both directions at once.
    violations = []
    for a in _SURFACE_VARIANTS:
        for b in _SURFACE_VARIANTS:
            if a == b:
                continue
            if ledger.exists():
                ledger.unlink()  # each combination judged from a clean slate
            r = _run(_payload("curl -sI %s/ ; curl -sI %s/" % (a, b),
                              "HTTP/1.1 200 OK\nserver: nginx\n"), vault)
            launched = "AUTO WEB-RECON" in r.stdout
            if _canon(a) == _canon(b):
                if not launched:
                    violations.append(
                        "FRAGMENTED one real surface into two (held, should launch): "
                        "%s + %s" % (a, b))
            elif launched:
                violations.append(
                    "LAUNCHED on another surface's evidence (the dangerous direction): "
                    "%s + %s" % (a, b))
            elif ledger.exists():
                violations.append(
                    "LEDGERED an undecided surface (a later turn can no longer "
                    "re-judge it): %s + %s -> %s" % (a, b, ledger.read_text().split()))
    assert not violations, "%d/%d combinations wrong:\n%s" % (
        len(violations), len(_SURFACE_VARIANTS) * (len(_SURFACE_VARIANTS) - 1),
        "\n".join(violations))


def test_out_of_scope_leg_of_the_command_still_counts_as_a_surface(vault):
    # Same whole-blob shortcut, reached from the other side: the blob covers BOTH legs of
    # the command, but only the in-scope one is ever judged, so counting surfaces from the
    # judged list alone makes a genuinely two-surface invocation look like one. The third
    # party's `server: nginx` must not decide the in-scope (possibly Cloudflare-fronted)
    # surface's verdict just because the leg that produced it was filtered out of scope.
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- cf.acme.internal\n\n## Out of scope\n- 10.0.0.1\n", encoding="utf-8")
    r = _run(_payload("curl -sI https://cf.acme.internal/ ; curl -sI https://thirdparty.example/",
                      "HTTP/1.1 200 OK\nserver: nginx\n"), vault)
    assert "AUTO WEB-RECON" not in r.stdout
    assert "cf.acme.internal" not in _ledger(vault)


def test_headers_printed_before_their_own_url_are_unattributable(vault):
    # Attribution slices forward from a URL literal, which assumes the layout "URL, then
    # the headers it labels". A loop like `curl -sI $u; echo $u` emits the reverse, so
    # forward slicing hands each surface the NEXT one's headers: here the Cloudflare host's
    # slice would pick up the plain host's `server: nginx` and launch scanners at the CDN.
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- a.acme.internal\n- b.acme.internal\n\n## Out of scope\n- 10.0.0.1\n",
        encoding="utf-8")
    cmd = "for u in https://a.acme.internal https://b.acme.internal; do curl -sI $u; echo $u; done"
    out = ("HTTP/2 200\nserver: cloudflare\ncf-ray: a258e1f1ffe2c9d5-VNO\n"
           "https://a.acme.internal\n"
           "HTTP/2 200\nserver: nginx\n"
           "https://b.acme.internal\n")
    r = _run(_payload(cmd, out), vault)
    assert "AUTO WEB-RECON" not in r.stdout
    assert _ledger(vault).strip() == ""


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


def test_blob_headers_never_clear_a_surface_only_a_live_probe_can(vault, tmp_path):
    # `curl --resolve h:443:<origin-ip>` silently points the TCP connection at a raw origin,
    # so the nginx header in the blob describes the ORIGIN while a scanner would resolve h
    # through DNS and hit the Cloudflare edge. There is ONE url literal, so the invocation
    # is a genuine singleton by the hook's own surface count and no attribution logic can
    # catch it. The only defence is the rule itself: blob text may suppress ("cf") but may
    # never clear -- a surface is cleared only by a live probe of the exact url a scanner
    # would be handed.
    #
    # This runs WITHOUT WEB_RECON_DRYRUN because that is the only mode where the rule is
    # observable: under DRYRUN the probe is skipped, so a removed blob-"clear" simply
    # becomes "unknown", and "clear" and "unknown" both launch. `curl` is stubbed to answer
    # the way the real edge does; recon-web.sh is stubbed to a no-op so a regression here
    # launches nothing real.
    (vault / "targets" / "acme" / "scope.md").write_text(
        "## In scope\n- cf.acme.internal\n\n## Out of scope\n- 10.0.0.1\n", encoding="utf-8")
    (vault / "scripts").mkdir(parents=True, exist_ok=True)
    (vault / "scripts" / "recon-web.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir()
    curl = stub_dir / "curl"
    curl.write_text("#!/bin/sh\nprintf 'HTTP/2 200\\r\\nserver: cloudflare\\r\\n'\n",
                    encoding="utf-8")
    curl.chmod(0o755)
    env = dict(os.environ, CLAUDEBRAIN_VAULT=str(vault),
               PATH=str(stub_dir) + os.pathsep + os.environ["PATH"])
    env.pop("WEB_RECON_DRYRUN", None)
    r = subprocess.run(["python3", HOOK], input=json.dumps(_payload(
        "curl -sI --resolve cf.acme.internal:443:203.0.113.9 https://cf.acme.internal/",
        "HTTP/1.1 200 OK\nserver: nginx\n")),
        capture_output=True, text=True, env=env, timeout=30)
    assert "AUTO WEB-RECON" not in r.stdout
    assert "CLOUDFLARE" in r.stdout
