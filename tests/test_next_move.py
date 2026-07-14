"""Tests for next_move.suggest heuristics across engagement types."""
import _engagement
import next_move


def _scope(**kw):
    base = {"in_scope": [], "out_of_scope": [], "allowed_tooling": [], "roe": [],
            "no_bruteforce": False, "no_dos": False, "passive_only": False}
    base.update(kw)
    return base


def _patch(monkeypatch, etype, state, loot, paths, scope=None, coverage=None):
    monkeypatch.setattr(_engagement, "active_dir", lambda: "/fake")
    monkeypatch.setattr(_engagement, "engagement_type", lambda d=None: etype)
    monkeypatch.setattr(_engagement, "scope", lambda d=None: scope or _scope())
    tables = {"state.md": state, "loot.md": loot, "paths.md": paths,
              "coverage.md": coverage or []}
    monkeypatch.setattr(_engagement, "_parse_table",
                        lambda p: tables.get(p.rsplit("/", 1)[-1], []))


def test_empty(monkeypatch):
    _patch(monkeypatch, "pentest", [], [], [])
    assert next_move.suggest() == ["No open moves. Recon more hosts or capture a cred."]


def test_open_path_ranks_first(monkeypatch):
    _patch(monkeypatch, "pentest", [], [],
           [{"path": "a->b", "status": "open", "next-move": "go"}])
    out = next_move.suggest()
    assert out[0].startswith("[now] a->b")


def test_dead_path_excluded(monkeypatch):
    _patch(monkeypatch, "pentest", [], [],
           [{"path": "x", "status": "dead", "next-move": "n"}])
    assert next_move.suggest() == ["No open moves. Recon more hosts or capture a cred."]


def test_pentest_spray_excludes_reused_host(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "PC1", "access": "port-open"}, {"host": "PC2", "access": "creds"}],
           [{"cred": "u:p", "status": "active", "reused-where": "PC2"}], [])
    out = " ".join(next_move.suggest())
    assert "spray u:p at PC1" in out
    assert "PC2" not in out  # already sprayed


def test_pentest_relay_blocked_without_cred(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "H", "access": "port-open", "signing": "False"}], [], [])
    out = " ".join(next_move.suggest())
    assert "relay blocked" in out


def test_acquisition_capped_at_three(monkeypatch):
    state = [{"host": f"H{i}", "access": "port-open", "services": "smb"} for i in range(6)]
    _patch(monkeypatch, "pentest", state, [], [])
    acq = [s for s in next_move.suggest(limit=99) if s.startswith("[acquire]")]
    assert len(acq) == 3


def test_bugbounty_uses_test_verb(monkeypatch):
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "access": "tested", "tech": "Node"}], [],
           [{"path": "ssrf->ato", "status": "open", "next-move": "oob"}])
    out = next_move.suggest()
    assert any(s.startswith("[now] ssrf->ato") for s in out)
    assert any("test: api.x" in s for s in out)


def test_ctf_uses_foothold_verb(monkeypatch):
    _patch(monkeypatch, "ctf",
           [{"target": "box1", "service": "http", "access": "port-open"}], [], [])
    out = " ".join(next_move.suggest())
    assert "get foothold: box1" in out


def test_bugbounty_no_pentest_relay(monkeypatch):
    # signing column absent for bugbounty; relay logic must not fire
    _patch(monkeypatch, "bugbounty", [{"asset": "a", "access": "recon"}], [], [])
    out = " ".join(next_move.suggest())
    assert "relay" not in out


def test_out_of_scope_host_filtered(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "ws1", "access": "port-open", "services": "smb"},
            {"host": "prod-db", "access": "port-open", "services": "smb"}],
           [], [], scope=_scope(out_of_scope=["prod-db"]))
    out = " ".join(next_move.suggest())
    assert "ws1" in out and "prod-db" not in out


def test_no_bruteforce_suppresses_spray(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "PC1", "access": "port-open", "signing": "False"}],
           [{"cred": "u:p", "status": "active", "reused-where": ""}], [],
           scope=_scope(no_bruteforce=True))
    out = " ".join(next_move.suggest())
    assert "spray" not in out and "relay-ready" not in out


def test_fingerprint_emits_test_move(monkeypatch):
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "tech": "GraphQL Apollo", "access": "tested"}], [], [])
    out = next_move.suggest()
    assert any(s.startswith("[test] api.x") and "introspection" in s
               and "hunt-injection" in s for s in out)


def test_suggest_json_parity_and_shape(monkeypatch):
    _patch(monkeypatch, "pentest", [], [],
           [{"path": "a->b", "status": "open", "next-move": "go"}])
    sj = next_move.suggest_json()
    assert sj and isinstance(sj[0], dict)
    assert set(sj[0]) == {"score", "tag", "text"}
    # parity: the string contract reflects the same ranked tuples
    assert next_move.suggest()[0] == f"[{sj[0]['tag']}] {sj[0]['text']}"


def test_suggest_json_empty_no_engagement(monkeypatch):
    monkeypatch.setattr(_engagement, "active_dir", lambda: None)
    assert next_move.suggest_json() == [] and next_move.suggest() == []


def test_fingerprint_priority_survives_truncation(monkeypatch):
    # one asset matching 6 fingerprints incl a prio-3 (ofbiz) + prio-1s (ldap/swagger).
    # tests[:4] must keep the critical and drop the info-level ones (the flat-85 bug).
    _patch(monkeypatch, "bugbounty",
           [{"asset": "host.x", "tech": "ldap swagger jenkins graphql redis ofbiz",
             "access": "tested"}], [], [])
    out = " ".join(next_move.suggest(limit=99))
    assert "CVE-2023-51467" in out          # prio-3 ofbiz survived the cap
    assert "anon bind" not in out           # prio-1 ldap truncated below it


def test_fingerprint_low_confidence_flagged(monkeypatch):
    # tech named only in free-text notes -> low-confidence flag, not a structured match
    _patch(monkeypatch, "bugbounty",
           [{"asset": "host.y", "notes": "banner suggests graphql", "access": "tested"}], [], [])
    out = " ".join(next_move.suggest())
    assert "low-confidence" in out


def test_fingerprint_suppressed_when_passive(monkeypatch):
    _patch(monkeypatch, "bugbounty",
           [{"asset": "api.x", "tech": "GraphQL", "access": "tested"}], [], [],
           scope=_scope(passive_only=True))
    out = " ".join(next_move.suggest())
    assert "[test]" not in out


def test_fingerprint_respects_scope(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "prod-db", "services": "mssql", "access": "port-open"}], [], [],
           scope=_scope(out_of_scope=["prod-db"]))
    out = " ".join(next_move.suggest())
    assert "prod-db" not in out


def test_passive_only_suppresses_acquisition(monkeypatch):
    _patch(monkeypatch, "pentest",
           [{"host": "PC1", "access": "port-open", "services": "smb"}], [],
           [{"path": "recon->lead", "status": "open", "next-move": "watch"}],
           scope=_scope(passive_only=True))
    out = next_move.suggest()
    assert any(s.startswith("[now] recon->lead") for s in out)
    assert not any(s.startswith("[acquire]") for s in out)


# --- coverage-gap floor moves -------------------------------------------------

def test_coverage_gap_surfaces_untested(monkeypatch):
    # in-scope asset, no coverage.md rows -> untested base classes enter the
    # shortlist as [gap] moves, highest-severity (list order) first.
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [])
    gaps = [s for s in next_move.suggest(limit=99) if s.startswith("[gap]")]
    assert gaps, "expected coverage-gap moves"
    assert "rce" in gaps[0]            # rce is first in the reordered bugbounty checklist


def test_coverage_gap_excludes_tested(monkeypatch):
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [],
           coverage=[{"asset": "api.x", "tested": "rce, sqli"}])
    gaps = " ".join(s for s in next_move.suggest(limit=99) if s.startswith("[gap]"))
    assert "rce" not in gaps and "sqli" not in gaps   # tested -> not a gap
    assert "ssrf" in gaps                              # still untested


def test_coverage_gap_capped_at_five(monkeypatch):
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [])
    gaps = [s for s in next_move.suggest(limit=99) if s.startswith("[gap]")]
    assert len(gaps) <= 5


def test_coverage_gap_ranks_below_concrete_moves(monkeypatch):
    # a gap floor move must never outrank an open path
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [],
           [{"path": "p", "status": "open", "next-move": "go"}])
    out = next_move.suggest(limit=99)
    assert out[0].startswith("[now]")
    now_i = next(i for i, s in enumerate(out) if s.startswith("[now]"))
    gap_i = next(i for i, s in enumerate(out) if s.startswith("[gap]"))
    assert now_i < gap_i


def test_coverage_gap_suppressed_when_passive(monkeypatch):
    _patch(monkeypatch, "bugbounty", [{"asset": "api.x", "access": "recon"}], [], [],
           scope=_scope(passive_only=True))
    assert not any(s.startswith("[gap]") for s in next_move.suggest(limit=99))


def test_coverage_gap_none_without_assets(monkeypatch):
    # no in-scope assets -> no gap moves (breadth is per-target, not free-floating)
    _patch(monkeypatch, "bugbounty", [], [], [])
    assert not any(s.startswith("[gap]") for s in next_move.suggest(limit=99))
