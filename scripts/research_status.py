#!/usr/bin/env python3
"""research_status.py - status + phase-aware next moves for the active research project.

Reads raw/research/<active>/{loop,findings,deadends}.md and prints the phase,
open hypotheses, finding/dead-end counts, and the moves appropriate to the
current phase. The research analog of next_move.py for engagements.

  python3 scripts/research_status.py        # full status + next moves
  python3 scripts/research_status.py -q      # one-line summary (SessionStart hook)
"""
import os
import re
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
RESEARCH = os.path.join(VAULT, "raw", "research")

PHASE_MOVES = {
    "setup": ["fill target.md (what / version / build / run)",
              "map the attack surface into surface.md (qmd_query the tech first)"],
    "surface-map": ["finish surface.md: entry points, parsers, dangerous sinks, deps with CVE history",
                    "write ranked hypotheses (<input/location> + <bug class> = <primitive>) in loop.md"],
    "surface": ["finish surface.md: entry points, parsers, dangerous sinks, deps",
                "write ranked hypotheses in loop.md"],
    "hypothesize": ["investigate the top open hypothesis (below)",
                    "skip anything already in deadends.md"],
    "investigate": ["evaluate the result: a finding -> findings.md then deepen; nothing -> deadends.md then next hypothesis",
                    "bound the effort, then pivot"],
    "deepen": ["on the current finding: root cause -> reachability -> exploitability -> impact -> variants"],
    "prove": ["minimal reproducible PoC in poc/",
              "novelty-check NVD / GHSA / changelog -> known? log+pivot. novel? candidate CVE"],
    "writeup": ["CVE-grade writeup in findings.md (root cause, PoC, CVSS, affected versions)",
                "invoke the disclosure skill to coordinate + request the CVE"],
}


def active_project():
    p = os.path.join(RESEARCH, "active.md")
    if not os.path.isfile(p):
        return None
    name = ""
    for line in open(p, encoding="utf-8", errors="ignore"):
        s = line.strip()
        if s and not s.startswith(("#", "<!--", "-")):
            name = s
            break
    d = os.path.join(RESEARCH, name)
    return d if name and os.path.isdir(d) else None


def _read(d, fn):
    p = os.path.join(d, fn)
    return open(p, encoding="utf-8", errors="ignore").read() if os.path.isfile(p) else ""


def parse_phase(loop):
    m = re.search(r"\*\*Phase:\*\*\s*(.+)", loop)
    if not m:
        return "setup"
    val = m.group(1).strip()
    if "|" in val or not val:          # template list left unfilled
        return "setup"
    return val.split()[0].lower()


def next_move_line(loop):
    m = re.search(r"\*\*Next move:\*\*\s*(.+)", loop)
    return m.group(1).strip() if m and m.group(1).strip() else ""


def open_hypotheses(loop):
    out = []
    if "## Hypotheses" not in loop:
        return out
    sec = loop.split("## Hypotheses", 1)[1].split("\n## ", 1)[0]
    for line in sec.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[0] in ("#", "") or set(cells[0]) <= set("-"):
            continue
        if "open" in cells[-1].lower() and cells[1]:
            out.append(cells[1])
    return out


def count_findings(text):
    cand = conf = 0
    for h in re.findall(r"##\s*FIND[^\n]*", text):
        hl = h.lower()
        if "confirmed" in hl:
            conf += 1
        elif "candidate" in hl:
            cand += 1
    return cand, conf


def count_deadends(text):
    # count real bullet rows (- or *, optional [x] checkbox, any non-space content),
    # skipping template placeholder lines (which carry a <...> token)
    return sum(1 for l in text.splitlines()
              if re.match(r"\s*[-*] (\[.\] )?\S", l) and "<" not in l)


COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def collect(d):
    loop = _read(d, "loop.md")
    phase = parse_phase(loop)
    hyps = open_hypotheses(loop)
    # strip template comment blocks so placeholder examples are not counted
    cand, conf = count_findings(COMMENT_RE.sub("", _read(d, "findings.md")))
    dead = count_deadends(COMMENT_RE.sub("", _read(d, "deadends.md")))
    moves = list(PHASE_MOVES.get(phase, PHASE_MOVES["setup"]))
    if phase in ("hypothesize", "investigate") and hyps:
        moves[0] = f"investigate top hypothesis: {hyps[0]}"
    nm = next_move_line(loop)
    if nm:
        moves.insert(0, nm)
    return {"name": os.path.basename(d), "phase": phase, "hyps": hyps,
            "cand": cand, "conf": conf, "dead": dead, "moves": moves}


def main():
    quiet = "-q" in sys.argv or "--summary" in sys.argv
    d = active_project()
    if not d:
        if not quiet:
            print("No active research project (set raw/research/active.md or run setup/new-research.sh).")
        return 0
    s = collect(d)
    if quiet:
        print(f"Research {s['name']}: phase {s['phase']} | {len(s['hyps'])} open hyp | "
              f"{s['cand']}c/{s['conf']}f findings, {s['dead']} dead-ends -> next: {s['moves'][0]}")
        return 0
    print(f"=== Research: {s['name']} ===")
    print(f"phase: {s['phase']} | findings: {s['cand']} candidate / {s['conf']} confirmed | dead-ends: {s['dead']}")
    if s["hyps"]:
        print("open hypotheses:")
        for h in s["hyps"][:5]:
            print(f"  - {h}")
    print("next moves:")
    for m in s["moves"][:4]:
        print(f"  -> {m}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
