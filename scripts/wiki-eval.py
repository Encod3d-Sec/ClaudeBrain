#!/usr/bin/env python3
"""wiki-eval.py - retrieval quality harness for the qmd-indexed wiki.

Reads a tracked gold set (scripts/wiki-eval-gold.json) of representative pentest queries,
each mapped to the canonical wiki page(s) that MUST rank. For each query it runs the qmd
CLI (semantic `qmd query`, or keyword `qmd keyword` when mode="keyword") and computes
hit@3, hit@5, and MRR, per-query and aggregate. Result paths are wiki-relative (e.g.
techniques/web/ssrf.md); a query hits if ANY of its expected paths is in the top-k (either
twin counts).

Read-only against the live index. Queries qmd in-process when its modules are importable (the
embedding model loads once and stays warm across all queries, ~10x faster than a fresh process
per query); falls back to the `qmd` CLI otherwise. QMD_VAULT is set automatically. Exit 0 for
reports; exit 1 for the gate modes (--verify-gold with a missing page, --check with a regression).

  python3 scripts/wiki-eval.py                 # human report (per-query + aggregate)
  python3 scripts/wiki-eval.py --json          # metrics as JSON (subagent/CI consumption)
  python3 scripts/wiki-eval.py --verify-gold   # assert every expected page exists on disk (exit 1 if not)
  python3 scripts/wiki-eval.py --baseline      # write scripts/wiki-eval-baseline.json from the current index
  python3 scripts/wiki-eval.py --check         # compare live eval to the baseline; exit 1 on regression
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
WIKI = os.path.join(VAULT, "wiki")
GOLD = os.path.join(VAULT, "scripts", "wiki-eval-gold.json")
BASELINE = os.path.join(VAULT, "scripts", "wiki-eval-baseline.json")
TOPN = 5
EPSILON = 0.001  # aggregate must not drop by more than this vs baseline

_SCORE = re.compile(r"^\[[0-9.]+\]\s+(.*)$")


def _blocks(stdout):
    """qmd prints, per result: a blank line, a result line, then up to ~300 chars of chunk
    text. Split on blank lines; the first line of each block is the candidate result line."""
    blocks, cur = [], []
    for ln in stdout.splitlines():
        if ln.strip() == "":
            if cur:
                blocks.append(cur)
                cur = []
        else:
            cur.append(ln)
    if cur:
        blocks.append(cur)
    return blocks


def parse_results(stdout):
    """Ranked wiki-relative paths from `qmd query` / `qmd keyword` stdout. Strips the
    [score] prefix (semantic) and accepts only path-shaped heads (ends .md, no spaces), so a
    prose text block is never mistaken for a result."""
    out = []
    for b in _blocks(stdout):
        head = b[0].strip()
        m = _SCORE.match(head)
        cand = (m.group(1) if m else head).strip()
        if cand.endswith(".md") and " " not in cand:
            out.append(cand)
    return out


_QMD = None  # lazy in-process handle: dict of callables, or False if qmd is not importable


def _qmd_inproc():
    """Load qmd's own query functions once (model stays warm across queries). Returns a dict of
    callables, or False if qmd cannot be imported (caller falls back to the CLI)."""
    global _QMD
    if _QMD is None:
        os.environ.setdefault("QMD_VAULT", VAULT)
        os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
        try:
            from qmd.embedder import embed_one
            from qmd.store import query_keyword, query_semantic
            _QMD = {"embed_one": embed_one, "semantic": query_semantic, "keyword": query_keyword}
        except Exception:
            _QMD = False
    return _QMD


def _dedupe(paths):
    """Order-preserving dedupe so hit@k is page-level (semantic results repeat a file across
    chunks)."""
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _run_inproc(query, mode, window):
    q = _qmd_inproc()
    if not q:
        return None
    try:
        if mode == "keyword":
            res = q["keyword"](query, window)
        else:
            res = q["semantic"](q["embed_one"](query), window)
        return [m["file"] for m in res["metadatas"][0]]
    except Exception:
        return None


def _run_subprocess(query, mode, window):
    cmd = "keyword" if mode == "keyword" else "query"
    env = dict(os.environ, QMD_VAULT=VAULT, HF_HUB_DISABLE_PROGRESS_BARS="1")
    try:
        out = subprocess.check_output(["qmd", cmd, query, "-n", str(window)], text=True, env=env,
                                      stderr=subprocess.DEVNULL, timeout=120)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return []
    return parse_results(out)


def run_query(query, mode, n=TOPN):
    """Ranked, page-level (deduped) wiki-relative paths for one query. Prefers qmd in-process
    (model loaded once, warm across queries); falls back to the `qmd` CLI. Fetches a wider
    window than n so dedupe still yields n distinct pages."""
    window = max(n * 3, 12)
    paths = _run_inproc(query, mode, window)
    if paths is None:
        paths = _run_subprocess(query, mode, window)
    return _dedupe(paths)


def hit_at(ranked, expected, k):
    return any(e in ranked[:k] for e in expected)


def reciprocal_rank(ranked, expected):
    for i, r in enumerate(ranked, 1):
        if r in expected:
            return 1.0 / i
    return 0.0


def load_gold():
    with open(GOLD, encoding="utf-8") as fh:
        return json.load(fh)["queries"]


def verify_gold(gold):
    """Return the list of expected paths that do not exist on disk."""
    missing = []
    for row in gold:
        for p in row["expected"]:
            if not os.path.isfile(os.path.join(WIKI, p)):
                missing.append(f'{p}  (query: "{row["query"]}")')
    return missing


def evaluate(gold, n=TOPN):
    per = []
    for row in gold:
        ranked = run_query(row["query"], row.get("mode", "semantic"), n)
        per.append({
            "query": row["query"],
            "expected": row["expected"],
            "hit@3": hit_at(ranked, row["expected"], 3),
            "hit@5": hit_at(ranked, row["expected"], 5),
            "rr": reciprocal_rank(ranked, row["expected"]),
            "top": ranked[:n],
        })
    q = len(per) or 1
    agg = {
        "hit@3": round(sum(p["hit@3"] for p in per) / q, 4),
        "hit@5": round(sum(p["hit@5"] for p in per) / q, 4),
        "mrr": round(sum(p["rr"] for p in per) / q, 4),
        "n_queries": len(per),
    }
    return {"aggregate": agg, "per_query": per}


def main():
    args = sys.argv[1:]

    gold = load_gold()

    if "--verify-gold" in args:
        missing = verify_gold(gold)
        if missing:
            print(f"wiki-eval: {len(missing)} gold expected-path(s) missing on disk:")
            for m in missing:
                print(f"  {m}")
            return 1
        print(f"wiki-eval: gold set OK ({len(gold)} queries, all expected pages exist).")
        return 0

    if not shutil.which("qmd") and not _qmd_inproc():
        print("wiki-eval: qmd not importable and `qmd` not on PATH; cannot run retrieval eval. "
              "(--verify-gold works without qmd.)", file=sys.stderr)
        return 1

    res = evaluate(gold)

    if "--baseline" in args:
        base = {
            "_comment": "Baseline metrics for scripts/wiki-eval.py --check, captured from the "
                        "clean index. Regenerate with: python3 scripts/wiki-eval.py --baseline. "
                        "The pytest gate fails if a live eval drops aggregate hit@3 below "
                        "baseline (minus epsilon) or flips a per-query hit@3 from true to false.",
            "captured": datetime.date.today().isoformat(),
            "aggregate": res["aggregate"],
            "per_query_hit3": {p["query"]: p["hit@3"] for p in res["per_query"]},
        }
        with open(BASELINE, "w", encoding="utf-8") as fh:
            json.dump(base, fh, indent=2)
            fh.write("\n")
        print(f"wiki-eval: wrote {os.path.relpath(BASELINE, VAULT)} "
              f"(hit@3={res['aggregate']['hit@3']}, mrr={res['aggregate']['mrr']}, "
              f"n={res['aggregate']['n_queries']}).")
        return 0

    if "--check" in args:
        if not os.path.isfile(BASELINE):
            print("wiki-eval: no baseline; run `python3 scripts/wiki-eval.py --baseline` first.",
                  file=sys.stderr)
            return 1
        with open(BASELINE, encoding="utf-8") as fh:
            base = json.load(fh)
        regressions = []
        if res["aggregate"]["hit@3"] < base["aggregate"]["hit@3"] - EPSILON:
            regressions.append(f'aggregate hit@3 {res["aggregate"]["hit@3"]} < baseline '
                               f'{base["aggregate"]["hit@3"]}')
        live = {p["query"]: p["hit@3"] for p in res["per_query"]}
        for query, was in base.get("per_query_hit3", {}).items():
            if was and not live.get(query, False):
                regressions.append(f'per-query regressed to miss: "{query}"')
        if regressions:
            print(f"wiki-eval CHECK FAIL: {len(regressions)} regression(s):")
            for r in regressions:
                print(f"  {r}")
            return 1
        print(f"wiki-eval CHECK OK: hit@3={res['aggregate']['hit@3']} "
              f">= baseline {base['aggregate']['hit@3']}; no per-query regressions.")
        return 0

    if "--json" in args:
        print(json.dumps(res, indent=2))
        return 0

    agg = res["aggregate"]
    print(f"Wiki retrieval eval  ({agg['n_queries']} queries)")
    print(f"  hit@3 = {agg['hit@3']}   hit@5 = {agg['hit@5']}   MRR = {agg['mrr']}")
    print("-" * 70)
    for p in res["per_query"]:
        mark = "ok " if p["hit@3"] else "MISS"
        print(f"  [{mark}] rr={p['rr']:.2f}  {p['query']}")
        if not p["hit@3"]:
            print(f"         expected {p['expected']}")
            print(f"         got      {p['top']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
