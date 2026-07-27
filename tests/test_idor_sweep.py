"""idor-sweep offline core: request parse, id detect, variant-set build, scope/RoE gating (--dry-run).
No VM dial; VAULT -> tmp for the fake engagement; _engagement imported from the real repo."""
import json
import os
import pathlib
import subprocess

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "burp" / "idor-sweep.py"


def _mk(tmp, eng, in_lines, flags=""):
    d = tmp / "targets" / eng
    d.mkdir(parents=True)
    body = "## In scope\n" + "".join("- %s\n" % x for x in in_lines) + "## Out of scope\n-\n"
    (d / "scope.md").write_text(("---\n%s---\n" % flags) + body)
    return d


def _req(tmp, name, text):
    p = tmp / name
    p.write_text(text)
    return str(p)


def _run(tmp, *args):
    env = dict(os.environ, VAULT=str(tmp), VM_SH="/bin/false")
    return subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True, env=env)


REQ = ("GET /api/v1/orders/12345 HTTP/1.1\r\nHost: shop.example.com\r\n"
       "Cookie: session=AAA\r\nAccept: */*\r\nConnection: close\r\n\r\n")


def test_dry_run_builds_owner_idor_enum_set(tmp_path):
    _mk(tmp_path, "e1", ["shop.example.com"])
    rf = _req(tmp_path, "r.txt", REQ)
    r = _run(tmp_path, "--dry-run", "e1", rf, "--attacker-auth", "Cookie: session=BBB", "--range", "2")
    assert r.returncode == 0, r.stderr
    plan = json.loads(r.stdout)
    labels = [x["label"] for x in plan["requests"]]
    ids = sorted(x["id"] for x in plan["requests"])
    assert "owner-baseline" in labels and "idor-test" in labels
    assert ids == [12343, 12344, 12345, 12345, 12346, 12347]      # owner+idor share 12345; enum ±2
    # idor-test + enum carry the attacker cookie; owner-baseline keeps the owner cookie
    owner = next(x for x in plan["requests"] if x["label"] == "owner-baseline")
    idor = next(x for x in plan["requests"] if x["label"] == "idor-test")
    assert any(k.lower() == "cookie" and v == "session=AAA" for k, v in owner["headers"])
    assert any(k.lower() == "cookie" and v == "session=BBB" for k, v in idor["headers"])


def test_no_bruteforce_forces_range_zero(tmp_path):
    _mk(tmp_path, "e2", ["shop.example.com"], flags="no_bruteforce: true\n")
    rf = _req(tmp_path, "r.txt", REQ)
    r = _run(tmp_path, "--dry-run", "e2", rf, "--range", "5")
    assert r.returncode == 0, r.stderr
    plan = json.loads(r.stdout)
    assert not [x for x in plan["requests"] if x["label"] == "enum"]   # no enumeration
    assert {x["label"] for x in plan["requests"]} == {"owner-baseline", "idor-test"}


def test_out_of_scope_host_refused(tmp_path):
    _mk(tmp_path, "e3", ["only-this.example.com"])
    rf = _req(tmp_path, "r.txt", REQ)   # host shop.example.com not in scope
    r = _run(tmp_path, "--dry-run", "e3", rf)
    assert r.returncode == 2
    assert "not in scope" in r.stderr.lower()


def test_passive_only_refused(tmp_path):
    _mk(tmp_path, "e4", ["shop.example.com"], flags="passive_only: true\n")
    rf = _req(tmp_path, "r.txt", REQ)
    r = _run(tmp_path, "--dry-run", "e4", rf)
    assert r.returncode == 2
    assert "passive_only" in r.stderr


def test_no_numeric_id_fails_loud(tmp_path):
    _mk(tmp_path, "e5", ["shop.example.com"])
    rf = _req(tmp_path, "r.txt", REQ.replace("/orders/12345", "/orders/me"))
    r = _run(tmp_path, "--dry-run", "e5", rf)
    assert r.returncode == 2
    assert "no numeric id" in r.stderr.lower()


def test_empty_in_scope_refused(tmp_path):
    _mk(tmp_path, "e6", [])
    rf = _req(tmp_path, "r.txt", REQ)
    r = _run(tmp_path, "--dry-run", "e6", rf)
    assert r.returncode == 2
    assert "no in_scope entries" in r.stderr.lower()


def test_url_form_scope_entry_matches_host(tmp_path):
    _mk(tmp_path, "e7", ["https://shop.example.com"])
    rf = _req(tmp_path, "r.txt", REQ)
    r = _run(tmp_path, "--dry-run", "e7", rf)
    assert r.returncode == 0, r.stderr


def test_bad_attacker_auth_clean_error(tmp_path):
    _mk(tmp_path, "e8", ["shop.example.com"])
    rf = _req(tmp_path, "r.txt", REQ)
    r = _run(tmp_path, "--dry-run", "e8", rf, "--attacker-auth", "NoColonHere")
    assert r.returncode == 2
    assert "Name: value" in r.stderr


import importlib.util
_spec = importlib.util.spec_from_file_location(
    "idor_sweep", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "burp" / "idor-sweep.py")
idor = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(idor)


def _r(label, id, status, length, h):
    return {"label": label, "id": id, "status": status, "length": length, "hash": h}


def test_verdict_flags_likely_idor_on_matching_body():
    v = idor.verdict([_r("owner-baseline", 5, 200, 1000, "H"),
                      _r("idor-test", 5, 200, 1000, "H")])
    assert v["idor"] == "LIKELY IDOR"


def test_verdict_authorization_enforced_on_403():
    v = idor.verdict([_r("owner-baseline", 5, 200, 1000, "H"),
                      _r("idor-test", 5, 403, 0, "X")])
    assert v["idor"] == "authorization enforced"


def test_verdict_warns_when_baseline_not_2xx():
    v = idor.verdict([_r("owner-baseline", 5, 401, 0, "X"),
                      _r("idor-test", 5, 200, 1000, "H")])
    assert "WARN" in v["idor"]


def test_verdict_counts_enum_accessible():
    v = idor.verdict([_r("owner-baseline", 5, 200, 100, "H"), _r("idor-test", 5, 403, 0, "X"),
                      _r("enum", 4, 200, 90, "A"), _r("enum", 6, 404, 0, "B")])
    assert v["enum_accessible"] == 1 and v["enum_total"] == 2
