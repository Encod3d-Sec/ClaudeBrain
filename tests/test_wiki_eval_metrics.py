"""Unit tests for scripts/wiki-eval.py PURE metric + parse functions. No qmd index, no
embedding model, no wiki required -- runs everywhere (CI-safe). The subprocess-backed
run_query / live eval are exercised only by the local-only gate (tests/test_wiki_eval.py)."""
import importlib.util
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "wiki-eval.py")
spec = importlib.util.spec_from_file_location("wiki_eval", SCRIPT)
we = importlib.util.module_from_spec(spec)
spec.loader.exec_module(we)

SEMANTIC = "\n[0.842] techniques/web/ssrf.md\nsome chunk text about ssrf\n\n[0.700] payloads/ssrf.md\nmore text\n\n[0.510] techniques/web/xxe.md\nnope\n"
KEYWORD = "\ntools/netexec.md\nnxc smb enumeration\n\ntools/nmap.md\nservice scan\n"


def test_parse_semantic_strips_score_and_keeps_paths():
    assert we.parse_results(SEMANTIC) == ["techniques/web/ssrf.md", "payloads/ssrf.md", "techniques/web/xxe.md"]


def test_parse_keyword_bare_paths():
    assert we.parse_results(KEYWORD) == ["tools/netexec.md", "tools/nmap.md"]


def test_parse_ignores_prose_blocks():
    # a prose paragraph (has spaces, not a .md path) must not be counted as a result
    assert we.parse_results("\n[0.9] techniques/web/xss.md\nthis is prose with a stray word.md inside\n") == ["techniques/web/xss.md"]


def test_hit_at_topk():
    ranked = ["a.md", "b.md", "c.md", "d.md"]
    assert we.hit_at(ranked, ["c.md"], 3) is True
    assert we.hit_at(ranked, ["d.md"], 3) is False
    assert we.hit_at(ranked, ["d.md"], 5) is True
    assert we.hit_at(ranked, ["x.md", "b.md"], 3) is True   # any expected counts (twins)


def test_reciprocal_rank():
    ranked = ["a.md", "b.md", "c.md"]
    assert we.reciprocal_rank(ranked, ["b.md"]) == 0.5
    assert we.reciprocal_rank(ranked, ["a.md"]) == 1.0
    assert we.reciprocal_rank(ranked, ["z.md"]) == 0.0
