"""Local-only retrieval regression gate. Skips on CI (wiki/ content, qmd, and the embedding
model are not present there). The paired visibility test xfails rather than silently passing so
an un-exercised gate is loud. Run locally with the wiki present and qmd importable / on PATH."""
import glob
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL = os.path.join(ROOT, "scripts", "wiki-eval.py")
BASELINE = os.path.join(ROOT, "scripts", "wiki-eval-baseline.json")

_WIKI_PRESENT = bool(glob.glob(os.path.join(ROOT, "wiki", "techniques", "**", "*.md"), recursive=True))
_QMD_PRESENT = shutil.which("qmd") is not None
_BASELINE_PRESENT = os.path.isfile(BASELINE)
_CAN_RUN = _WIKI_PRESENT and _QMD_PRESENT and _BASELINE_PRESENT

_needs_index = pytest.mark.skipif(
    not _CAN_RUN,
    reason="retrieval eval needs wiki/ + qmd + a captured baseline; local-only gate",
)


def test_wiki_eval_gate_visible():
    if not _CAN_RUN:
        pytest.xfail("retrieval eval gate NOT exercised this run (missing wiki/, qmd, or "
                     "baseline) - this is not a pass. Run locally with the index present.")
    assert True


@_needs_index
def test_verify_gold_paths_exist():
    r = subprocess.run([sys.executable, EVAL, "--verify-gold"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, f"gold set points at a missing page:\n{r.stdout}"


@_needs_index
def test_retrieval_no_regression_vs_baseline():
    r = subprocess.run([sys.executable, EVAL, "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, f"retrieval regressed vs baseline:\n{r.stdout}"
