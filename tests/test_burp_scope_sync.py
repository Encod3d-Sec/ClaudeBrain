"""burp-scope-sync --dry-run: scope.md -> Burp advanced-scope host regexes, offline (no VM dial).
VAULT is pointed at a tmp dir for the fake engagement; _engagement is imported from the real repo."""
import json
import os
import pathlib
import subprocess

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "burp-scope-sync.py"


def _mk(tmp, eng, in_lines, out_lines=()):
    d = tmp / "targets" / eng
    d.mkdir(parents=True)
    body = "## In scope\n" + "".join("- %s\n" % x for x in in_lines)
    body += "## Out of scope\n" + "".join("- %s\n" % x for x in out_lines)
    (d / "scope.md").write_text(body)
    return d


def _run(tmp, *args):
    env = dict(os.environ, VAULT=str(tmp), VM_SH="/bin/false")
    return subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True, env=env)


def test_dry_run_builds_precise_regexes(tmp_path):
    _mk(tmp_path, "e1", ["10.0.0.5", "example.com", "10.112.0.0/16"])
    r = _run(tmp_path, "--dry-run", "e1")
    assert r.returncode == 0, r.stderr
    cfg = json.loads(r.stdout)
    sc = cfg["target"]["scope"]
    hosts = [e["host"] for e in sc["include"]]
    assert sc["advanced_mode"] is True
    assert r"^10\.0\.0\.5$" in hosts            # bare IP, anchored (precise)
    assert r"^(.*\.)?example\.com$" in hosts    # domain incl subdomains
    assert r"^10\.112\." in hosts               # octet-aligned /16 -> prefix regex


def test_non_octet_cidr_is_skipped_failclosed(tmp_path):
    # a /12 is not octet-aligned -> skipped (never widen scope to over-approve), warned on stderr
    _mk(tmp_path, "e2", ["10.96.0.0/12", "1.2.3.4"])
    r = _run(tmp_path, "--dry-run", "e2")
    assert r.returncode == 0, r.stderr
    cfg = json.loads(r.stdout)
    hosts = [e["host"] for e in cfg["target"]["scope"]["include"]]
    assert hosts == [r"^1\.2\.3\.4$"]           # only the plain IP; the /12 is dropped
    assert "NOT auto-approving" in r.stderr and "10.96.0.0/12" in r.stderr


def test_empty_scope_errors(tmp_path):
    _mk(tmp_path, "e3", [])
    r = _run(tmp_path, "--dry-run", "e3")
    assert r.returncode == 3
    assert "no In-scope" in r.stderr
