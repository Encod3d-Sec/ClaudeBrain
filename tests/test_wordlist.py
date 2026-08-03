"""wordlist-suggest.py: mines generic path/param tokens from targets/ but never leaks
client markers (IPs, scope hosts/domains, engagement names, flags, filesystem paths)."""
import os
import pathlib
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUGGEST = os.path.join(REPO, "scripts", "wordlist-suggest.py")


def _vault(tmp):
    eng = pathlib.Path(tmp) / "targets" / "acme"
    eng.mkdir(parents=True)
    (eng / "scope.md").write_text("## In scope\n- acme.example.com\n- 10.9.9.9\n")
    (eng / "walkthrough.md").write_text(
        "foothold at http://10.9.9.9/widgetpanel ; pivot to https://kyc.acme.example.com/x\n"
        "flag THM{secret_flag_here}. SSRF: http://t/fetch?proxytarget=http://127.0.0.1\n"
        "route /coolfeature ; read /etc/passwd via cat ; field name=\"shipid\".\n")
    return tmp


def test_suggest_finds_generic_blocks_leaks(tmp_path):
    out = subprocess.run(
        ["python3", SUGGEST], capture_output=True, text=True,
        env=dict(os.environ, CLAUDEBRAIN_VAULT=_vault(str(tmp_path)))).stdout
    # generic tokens ARE surfaced
    assert "widgetpanel" in out and "coolfeature" in out      # path segments
    assert "proxytarget" in out and "shipid" in out           # param names
    # client markers are NEVER surfaced
    for bad in ("10.9.9.9", "acme", "example", "kyc", "passwd", "flag", "secret_flag_here"):
        assert bad not in out, f"LEAK: {bad!r} surfaced in suggestions"


def _vault_ids(tmp):
    eng = pathlib.Path(tmp) / "targets" / "acme"
    eng.mkdir(parents=True)
    (eng / "scope.md").write_text("## In scope\n- acme.example.com\n")
    (eng / "walkthrough.md").write_text(
        "IDOR http://acme.example.com/api/550e8400-e29b-41d4-a716-446655440000/profile\n"
        "object /users/a1b2c3d4e5f6a7b8/orders and /obj/deadbeefcafebabe/edit\n"
        "ticket http://acme.example.com/t/2024081500123456/view ; route /coolfeature\n")
    return tmp


def test_opaque_object_ids_never_leak(tmp_path):
    """UUIDs / long-hex / digit-heavy per-object IDs (IDOR/customer IDs) must never surface."""
    out = subprocess.run(
        ["python3", SUGGEST], capture_output=True, text=True,
        env=dict(os.environ, CLAUDEBRAIN_VAULT=_vault_ids(str(tmp_path)))).stdout
    for leak in ("550e8400", "e29b", "446655440000", "a1b2c3d4e5f6a7b8",
                 "deadbeefcafebabe", "2024081500123456"):
        assert leak not in out, f"LEAK: opaque id {leak!r} surfaced"
    assert "coolfeature" in out      # a genuine route in the same blob still surfaces


def test_suggest_empty_vault_is_quiet(tmp_path):
    (pathlib.Path(tmp_path) / "targets").mkdir()
    out = subprocess.run(
        ["python3", SUGGEST], capture_output=True, text=True,
        env=dict(os.environ, CLAUDEBRAIN_VAULT=str(tmp_path))).stdout
    assert "no new generic candidates" in out
