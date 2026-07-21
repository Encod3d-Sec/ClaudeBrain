#!/usr/bin/env python3
"""PostToolUse(Write|Edit) hook: auto-reindex the qmd search index after a wiki edit.

When a Write/Edit lands on a wiki/**/*.md page, fire a debounced background `qmd update`
so the change is searchable without the manual reindex step. Anything else returns
immediately -- a non-wiki write costs one endswith + substring check, no latency.

Debounce: a burst of edits collapses to one reindex (a stamp file gates re-firing inside
the window; the reindex runs `sleep <window>; qmd update` detached so trailing edits land
before qmd rescans disk). Off the blocking path: the reindex is a detached background
process, so the hook returns at once. Fail-open: any error exits 0.

Ships code + registration only; it runs live after the operator re-runs
setup/install-hooks.sh and restarts.
"""
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
DEBOUNCE_SECONDS = 15   # collapse an edit burst into one reindex; qmd update rescans disk


def _is_wiki_md(path):
    """True iff path points at a markdown file under a wiki/ directory."""
    if not path or not path.endswith(".md"):
        return False
    norm = path.replace("\\", "/")
    return "/wiki/" in norm or norm.startswith("wiki/")


def _vault():
    return (os.environ.get("QMD_VAULT") or os.environ.get("CLAUDEBRAIN_VAULT")
            or os.path.dirname(os.path.dirname(HERE)))


def _due(stamp, now):
    """Leading-edge debounce: due unless a reindex was already scheduled within the window."""
    try:
        return now - os.path.getmtime(stamp) >= DEBOUNCE_SECONDS
    except OSError:
        return True   # no stamp yet -> due


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        return
    if data.get("tool_name") not in ("Write", "Edit"):
        return
    path = (data.get("tool_input") or {}).get("file_path", "")
    if not _is_wiki_md(path):
        return   # not a wiki page -> instant no-op, zero latency on unrelated writes

    vault = _vault()
    stamp = os.path.join(vault, ".wiki-reindex-stamp")
    if not _due(stamp, time.time()):
        return   # a reindex already fired inside the debounce window
    try:
        open(stamp, "w").close()   # debounce anchor (and the "acted" observable for tests)
    except OSError:
        pass

    # Fire the reindex OFF the blocking path: a detached background process, so the hook
    # returns immediately. `sleep` lets a burst's trailing edits land before qmd rescans.
    # Skip when qmd is not installed (nothing to run; keeps tests from spawning anything).
    if shutil.which("qmd"):
        try:
            subprocess.Popen(
                ["sh", "-c", "sleep %d; qmd update" % DEBOUNCE_SECONDS],
                cwd=vault, env=dict(os.environ, QMD_VAULT=vault),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
