"""Unit tests for scripts/wiki-wiring-audit.py's own logic, isolated from the real (gitignored)
wiki/ content via monkeypatched paths. Regression guard for the duplicate-slug bug: two files
sharing a basename across different subtrees (e.g. payloads/xss.md + techniques/web/xss.md, of
which 13 pairs exist in the real wiki) must NOT cause one to silently vanish from the audit, and
an anchor page's one-hop links must be unioned across every file sharing its slug.
"""
import importlib.util
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "wiki-wiring-audit.py")

spec = importlib.util.spec_from_file_location("wiki_wiring_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _isolated(tmp_path, monkeypatch):
    """Point every module path constant at a fresh tmp_path wiki, so real vault content
    never leaks into these assertions."""
    wiki = tmp_path / "wiki"
    monkeypatch.setattr(audit, "WIKI", str(wiki))
    monkeypatch.setattr(audit, "PLAYBOOK", str(tmp_path / "playbook.json"))
    monkeypatch.setattr(audit, "SKILLS_GLOB", str(tmp_path / "skills" / "**" / "*.md"))
    monkeypatch.setattr(audit, "EXEMPT_FILE", str(tmp_path / "wiring-exempt.txt"))
    return wiki


def test_duplicate_slug_both_files_are_audited_not_dropped(tmp_path, monkeypatch):
    wiki = _isolated(tmp_path, monkeypatch)
    # two files, same basename, different subtrees -- the exact collision shape in the real wiki
    _write(str(wiki / "payloads" / "xss.md"), "---\ntitle: x\n---\n# payload xss\n")
    _write(str(wiki / "techniques" / "web" / "xss.md"), "---\ntitle: x\n---\n# technique xss\n")
    (tmp_path / "playbook.json").write_text(json.dumps({"fingerprints": {}}), encoding="utf-8")

    pages = audit.audited_pages()
    assert "xss" in pages
    assert len(pages["xss"]) == 2, "both same-slug files must be tracked, not just one"
    paths = {os.path.relpath(p, str(wiki)) for p in pages["xss"]}
    assert paths == {os.path.join("payloads", "xss.md"), os.path.join("techniques", "web", "xss.md")}


def test_one_hop_unions_links_across_duplicate_anchor_slug(tmp_path, monkeypatch):
    wiki = _isolated(tmp_path, monkeypatch)
    # an anchor slug ("hub") resolves to TWO files; only one of them actually links the child.
    # The one-hop expansion must still find it regardless of which file glob() enumerates first.
    _write(str(wiki / "cheatsheets" / "hub.md"), "---\ntitle: h\n---\nno links here\n")
    _write(str(wiki / "techniques" / "linux" / "hub.md"), "---\ntitle: h\n---\nsee [[child-technique]]\n")
    _write(str(wiki / "techniques" / "linux" / "child-technique.md"), "---\ntitle: c\n---\n# child\n")
    (tmp_path / "playbook.json").write_text(
        json.dumps({"fingerprints": {"pat": {"refs": ["hub"]}}}), encoding="utf-8"
    )

    pages, wired, exempt, orphans, anchors = audit.compute()
    assert "hub" in anchors
    assert "child-technique" not in orphans, (
        "child-technique is one-hop reachable via the techniques/linux/hub.md twin of the 'hub' "
        "anchor; picking only the cheatsheets/hub.md twin (which has no links) must not lose it"
    )


def test_total_counts_files_not_unique_slugs(tmp_path, monkeypatch, capsys):
    wiki = _isolated(tmp_path, monkeypatch)
    _write(str(wiki / "payloads" / "dup.md"), "---\ntitle: d\n---\n# a\n")
    _write(str(wiki / "techniques" / "web" / "dup.md"), "---\ntitle: d\n---\n# b\n")
    (tmp_path / "playbook.json").write_text(json.dumps({"fingerprints": {}}), encoding="utf-8")

    pages, *_ = audit.compute()
    total = sum(len(v) for v in pages.values())
    assert total == 2, "two distinct files sharing a slug must both count toward the total"


def _rel(wiki, sub, *parts):
    return os.path.join(str(wiki), sub, *parts)


def test_twin_pairs_detects_payload_technique_collision(tmp_path, monkeypatch):
    wiki = _isolated(tmp_path, monkeypatch)
    _write(_rel(wiki, "payloads", "ssrf.md"), "---\ntitle: p\n---\nx\n")
    _write(_rel(wiki, "techniques", "web", "ssrf.md"), "---\ntitle: t\n---\nx\n")
    _write(_rel(wiki, "techniques", "web", "solo.md"), "---\ntitle: s\n---\nx\n")  # no twin
    pairs = audit.twin_pairs(audit.audited_pages())
    assert len(pairs) == 1
    pay, tech = pairs[0]
    assert pay.endswith(os.path.join("payloads", "ssrf.md"))
    assert tech.endswith(os.path.join("web", "ssrf.md"))


def test_twin_link_violations_flags_missing_and_passes_when_mutual(tmp_path, monkeypatch):
    wiki = _isolated(tmp_path, monkeypatch)
    # payload links technique path-qualified; technique does NOT link back -> one violation
    _write(_rel(wiki, "payloads", "ssrf.md"), "---\ntitle: p\n---\nFull methodology: [[techniques/web/ssrf]].\n")
    _write(_rel(wiki, "techniques", "web", "ssrf.md"), "---\ntitle: t\n---\nno backlink here\n")
    v = audit.twin_link_violations(audit.audited_pages())
    assert len(v) == 1
    assert v[0]["direction"] == "technique->payload"
    assert v[0]["missing_link"] == "payloads/ssrf"

    # now add the backlink -> zero violations
    _write(_rel(wiki, "techniques", "web", "ssrf.md"), "---\ntitle: t\n---\nQuick payloads: [[payloads/ssrf]].\n")
    assert audit.twin_link_violations(audit.audited_pages()) == []


def test_twin_link_bare_slug_does_not_satisfy(tmp_path, monkeypatch):
    # a bare [[ssrf]] is ambiguous between the twins; it must NOT count as a mutual link
    wiki = _isolated(tmp_path, monkeypatch)
    _write(_rel(wiki, "payloads", "ssrf.md"), "---\ntitle: p\n---\nsee [[ssrf]]\n")
    _write(_rel(wiki, "techniques", "web", "ssrf.md"), "---\ntitle: t\n---\nsee [[ssrf]]\n")
    v = audit.twin_link_violations(audit.audited_pages())
    assert {x["direction"] for x in v} == {"payload->technique", "technique->payload"}


def test_twin_link_inside_code_fence_does_not_satisfy(tmp_path, monkeypatch):
    # a path-qualified link buried in a fenced code block is not a functional link -> violation.
    # Regression guard for the mfa-bypass bug the no-fence-aware check let pass green.
    wiki = _isolated(tmp_path, monkeypatch)
    _write(_rel(wiki, "payloads", "ssrf.md"),
           "---\ntitle: p\n---\n```\n[[techniques/web/ssrf]]\n```\n")
    _write(_rel(wiki, "techniques", "web", "ssrf.md"),
           "---\ntitle: t\n---\nQuick payloads: [[payloads/ssrf]].\n")
    v = audit.twin_link_violations(audit.audited_pages())
    assert [x["direction"] for x in v] == ["payload->technique"], (
        "the payload page's only link is inside a code fence, so it must be flagged missing"
    )
