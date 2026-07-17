#!/usr/bin/env python3
"""On-demand engagement status dashboard -- one consolidated glance for operator observability.

Composes the active engagement's counts (_engagement.summary), kill-chain phase (the board),
evidence actually captured (poc/ + recon/ shots), recent dead-ends, and the ranked next moves
(ranking stays in scripts/next_move.py -- not duplicated here). Read-only; never edits the
engagement. Run any time:

    python3 scripts/status.py

The same render is surfaced compactly at SessionStart by engagement-init; this is the full
on-demand view (evidence + dead-ends included) the operator can pull mid-engagement.
"""
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))


def evidence_counts(d):
    """(poc_shots, recon_cards): deliberate PoC images under poc/ (recursive) + auto recon cards."""
    poc = len(glob.glob(os.path.join(d, "poc", "**", "*.png"), recursive=True))
    recon = len(glob.glob(os.path.join(d, "recon", "*.png")))
    return poc, recon


def deadend_lines(d, limit=3):
    """The most recent Dead-ends.md bullet lines (skip headers/frontmatter/blank)."""
    p = os.path.join(d, "Deadends.md")
    if not os.path.isfile(p):
        return []
    out = []
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.strip()
        if s.startswith("- ") and len(s) > 2:
            body = s[2:].strip()
            # skip template placeholders: a bare/empty checkbox line carries no dead-end
            if body and not re.fullmatch(r"\[[ x!~-]?\]", body):
                out.append(body)
    return out[-limit:]


def board_phase(d):
    """(where, open_n, dead_n) from killchain.md: highest-numbered phase with an open item.
    Mirrors engagement-init.board_status; kept here so status.py has no hook dependency."""
    p = os.path.join(d, "killchain.md")
    if not os.path.isfile(p):
        return None
    open_n = dead_n = 0
    phase = cur = None
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.rstrip()
        hm = re.match(r"##\s+(\d+)\.\s+([^(]+)", s)
        if hm:
            phase = (int(hm.group(1)), hm.group(2).strip())
            continue
        if "[ ]" in s or "[~]" in s:
            open_n += 1
            if phase and (cur is None or phase[0] >= cur[0]):
                cur = phase
        elif "[!]" in s:
            dead_n += 1
    where = ("Phase %d %s" % cur) if cur else "complete"
    return where, open_n, dead_n


def render(name, etype, solved, summ, board, poc, recon, deads, moves_text):
    """Pure formatter -> the dashboard string. All inputs are precomputed (testable)."""
    head = "=== %s (%s)%s ===" % (name, etype, "  STATUS: SOLVED" if solved else "")
    lines = [head]
    if summ:
        lines.append("hosts %d (owned %d) | creds %d | open paths %d"
                     % (summ["hosts"], summ["owned"], summ["creds"], summ["open_paths"]))
    if board:
        where, open_n, dead_n = board
        lines.append("board: %s | %d open | %d deadends" % (where, open_n, dead_n))
    lines.append("evidence: %d poc shot(s), %d recon card(s)" % (poc, recon))
    if deads:
        lines.append("recent deadends:")
        lines += ["  - " + x for x in deads]
    if moves_text.strip():
        lines.append(moves_text.strip())
    return "\n".join(lines)


def main():
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        d = None
    if not d:
        print("No active engagement (targets/active.md).")
        return 0
    name = os.path.basename(d)
    etype = _engagement.engagement_type(d)
    solved = _engagement.is_solved(d)
    summ = _engagement.summary()
    board = board_phase(d)
    poc, recon = evidence_counts(d)
    deads = deadend_lines(d)
    moves_text = ""
    try:
        r = subprocess.run([sys.executable, os.path.join(HERE, "next_move.py")],
                           capture_output=True, text=True, timeout=25)
        moves_text = r.stdout or ""
    except Exception:
        pass
    print(render(name, etype, solved, summ, board, poc, recon, deads, moves_text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
