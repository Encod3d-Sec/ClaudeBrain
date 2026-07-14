"""CVE drift oracle: detects recent high/crit CVEs missing from playbook fingerprints."""
import cve_feed

# fixture corpus: a new jenkins crit (missing), one already in the playbook,
# one too old, one too low-severity. Only the first should be reported.
JSONL = "\n".join([
    '{"ID":"CVE-2025-99999","Info":{"Name":"Jenkins X RCE","Severity":"critical","Description":"jenkins remote code execution"}}',
    '{"ID":"CVE-2024-23897","Info":{"Name":"Jenkins CLI","Severity":"high","Description":"jenkins arbitrary file read"}}',
    '{"ID":"CVE-2019-1111","Info":{"Name":"Jenkins old","Severity":"critical","Description":"jenkins old bug"}}',
    '{"ID":"CVE-2025-88888","Info":{"Name":"Jenkins info","Severity":"medium","Description":"jenkins minor"}}',
]) + "\n"


def _corpus(tmp_path):
    c = tmp_path / "nt"
    c.mkdir()
    (c / "cves.json").write_text(JSONL, encoding="utf-8")
    return str(c)


def test_cve_feed_detects_recent_missing(tmp_path):
    res = cve_feed.drift(_corpus(tmp_path))
    jen = [r for r in res if r[0] == "Jenkins"]
    assert jen, "jenkins drift not detected"
    assert jen[0][2] == ["CVE-2025-99999"]   # only the new crit; others excluded


def test_cve_feed_excludes_known_old_and_low(tmp_path):
    res = cve_feed.drift(_corpus(tmp_path))
    allcves = {c for _, _, m in res for c in m}
    assert "CVE-2024-23897" not in allcves   # already cited in playbook tests[]
    assert "CVE-2019-1111" not in allcves     # older than MIN_YEAR
    assert "CVE-2025-88888" not in allcves     # severity below high


def test_cve_feed_no_corpus_returns_none(monkeypatch):
    monkeypatch.setattr(cve_feed, "corpus_dir", lambda: None)
    assert cve_feed.drift() is None


def test_cve_feed_match_key_word_boundary():
    fps = {"wordpress|wp-": {}, "next\\.js|nextjs|/_next/static": {}}
    assert cve_feed._match_key("next", fps) == "next\\.js|nextjs|/_next/static"
    assert cve_feed._match_key("word", fps) is None            # must NOT bind to 'wordpress'
    assert cve_feed._match_key("wordpress", fps) == "wordpress|wp-"
