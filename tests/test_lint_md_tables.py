"""Tests for scripts/lint-md-tables.py (GFM table-integrity linter).

Hyphenated filename -> load via importlib (mirrors tests/test_check_hooks.py).
"""
import importlib.util
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    spec = importlib.util.spec_from_file_location(
        "lint_md_tables", os.path.join(REPO, "scripts", "lint-md-tables.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_flags_column_mismatch():
    lmt = _load()
    text = "| a | b |\n|---|---|\n| 1 | 2 | 3 |\n"
    issues = lmt.lint_text(text)
    assert issues and any("cells" in m for _, m in issues)
    assert issues[0][0] == 3  # the offending data row line number


def test_flags_blank_line_split():
    lmt = _load()
    text = "| a | b |\n|---|---|\n\n| 1 | 2 |\n"
    issues = lmt.lint_text(text)
    assert any("detached" in m for _, m in issues)


def test_clean_table_passes():
    lmt = _load()
    text = "text\n\n| a | b |\n|---|---|\n| 1 | 2 |\n| 3 | 4 |\n\nmore prose\n"
    assert lmt.lint_text(text) == []


def test_two_adjacent_valid_tables_pass():
    lmt = _load()
    # a blank line before a NEW header+separator is a legit second table, not a split
    text = ("| a | b |\n|---|---|\n| 1 | 2 |\n\n"
            "| c | d |\n|---|---|\n| 3 | 4 |\n")
    assert lmt.lint_text(text) == []


def test_lint_paths_recurses_dir(tmp_path):
    lmt = _load()
    (tmp_path / "good.md").write_text("| a | b |\n|---|---|\n| 1 | 2 |\n")
    (tmp_path / "bad.md").write_text("| a | b |\n|---|---|\n| 1 |\n")
    (tmp_path / "ignore.txt").write_text("| a | b |\n|---|---|\n| 1 |\n")
    hits = lmt.lint_paths([str(tmp_path)])
    assert len(hits) == 1
    assert hits[0][0].endswith("bad.md")


def test_demo_self_check_runs():
    lmt = _load()
    lmt.demo()  # asserts internally; must not raise
