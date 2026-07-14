#!/usr/bin/env python3
"""SessionStart hook: self-heal engagement state + inject summary + gap report.

- Creates any missing state/loot/paths files in the active engagement from
  templates (self-heal; never overwrites).
- Injects the active-engagement summary.
- Reports the count of missing wiki technique pages (scripts/wiki-gaps.py).
- Keeps wiki/index.md fresh (scripts/gen_index.py, idempotent) and surfaces a
  wiki integrity summary (scripts/lint-wiki.py) only when something is broken.
- Surfaces the active research project's loop state + next moves
  (scripts/research_status.py, from raw/research/active.md) when one is set.

Plain stdout is added to context, alongside the other SessionStart hooks
(caveman, hot.md). Non-fatal: any error exits 0 silent.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _run_script(name, *args, timeout=40):
    """Run scripts/<name> from the vault; return CompletedProcess or None."""
    try:
        import _engagement
        script = os.path.join(_engagement.VAULT, "scripts", name)
        return subprocess.run(
            ["python3", script, *args],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None


def wiki_gap_count():
    r = _run_script("wiki-gaps.py")
    if r is None:
        return None
    return len([x for x in r.stdout.splitlines() if x.strip()])


def regen_index():
    """Keep wiki/index.md current (writes only when stale; no churn when fresh)."""
    _run_script("gen_index.py", timeout=30)


def wiki_lint_summary():
    """One-line wiki integrity summary, or None when clean."""
    r = _run_script("lint-wiki.py", "-q")
    if r is None:
        return None
    line = r.stdout.strip()
    return line or None


def wordlist_candidates():
    """(paths, params) count of NEW generic wordlist tokens minable from targets/, or None."""
    r = _run_script("wordlist-suggest.py", "--count", timeout=20)
    if r is None:
        return None
    try:
        p, q = r.stdout.split()
        return (int(p), int(q))
    except Exception:
        return None


def wiki_candidate_count():
    """Pending candidates in the active engagement's wiki-candidates/ inbox, or 0.
    Silent-at-zero surfacer, same shape as the wordlist nag. Best-effort.

    Detects pending by PARSING frontmatter via _engagement._frontmatter (the same
    tolerant parser wiki-promote.py's pending-detection uses), not a raw
    "status: pending" substring - a raw substring misses e.g. 'status:  pending'
    (extra spacing), silently undercounting a candidate that IS promotable."""
    try:
        import _engagement
        d = _engagement.active_dir()
        if not d:
            return 0
        inbox = os.path.join(d, "wiki-candidates")
        if not os.path.isdir(inbox):
            return 0
        n = 0
        for f in os.listdir(inbox):
            if not f.endswith(".md") or f.startswith("_"):
                continue
            text = open(os.path.join(inbox, f), encoding="utf-8", errors="ignore").read()
            fm = _engagement._frontmatter(text)
            if fm.get("status", "").strip().lower() == "pending":
                n += 1
        return n
    except Exception:
        return 0


def research_status_text():
    """Full status block for the active research project, or None if none set."""
    r = _run_script("research_status.py", timeout=15)
    if r is None:
        return None
    out = r.stdout.strip()
    return out if out and "No active research project" not in out else None


def _stamp_path():
    import _engagement
    return os.path.join(_engagement.VAULT, ".wiki-stamp")


def wiki_fingerprint():
    """Cheap max-mtime over wiki/ + triggers.json + playbook.json (stat only, no reads).
    Detects any page add/remove/edit so the heavy walks run only when needed."""
    import _engagement
    mx = 0.0
    stack = [os.path.join(_engagement.VAULT, "wiki")]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    else:
                        m = e.stat(follow_symlinks=False).st_mtime
                        if m > mx:
                            mx = m
        except OSError:
            pass
    for f in ("skills/hunt/triggers.json", "scripts/playbook.json"):
        try:
            m = os.stat(os.path.join(_engagement.VAULT, f)).st_mtime
            if m > mx:
                mx = m
        except OSError:
            pass
    return f"{mx:.3f}"


def wiki_changed():
    """(changed, fingerprint). True if wiki/triggers/playbook changed since last stamp."""
    fp = wiki_fingerprint()
    try:
        old = open(_stamp_path(), encoding="utf-8").read().strip()
    except OSError:
        old = ""
    return (fp != old, fp)


def write_stamp(fp):
    try:
        open(_stamp_path(), "w", encoding="utf-8").write(fp)
    except OSError:
        pass


def main():
    try:
        import _engagement
    except Exception:
        return

    out = []
    created = _engagement.ensure_state_files()
    if created:
        out.append("Self-heal: created " + ", ".join(created) + " from template.")

    summ = _engagement.summary_text()
    if summ:
        out.append(summ)

    sc = _engagement.scope_text()
    if sc:
        out.append(sc)

    # tunnel_safe is an affirmation, not a forbidden flag, so scope_text (RoE-forbidden
    # list) omits it. Surface it explicitly so the model knows curl+nc is the intended
    # tool here (scanners exhaust the pivot's conntrack). Silent when unset.
    try:
        if _engagement.scope().get("tunnel_safe"):
            out.append("tunnel_safe: curl+nc only (scanners kill the pivot)")
    except Exception:
        pass

    # OOB callback HITs land the highest: a confirmed blind-bug callback should be
    # turned into a FIND immediately. Surfaced above next-moves.
    try:
        hits = _engagement.oob_hits()
        if hits:
            sinks = "; ".join((h.get("sink") or h.get("token") or "?") for h in hits[:4])
            out.append(f"OOB HIT: {len(hits)} callback(s) landed ({sinks}) -> scaffold + "
                       "validate the FIND(s), then mark the oob.md row 'actioned'.")
    except Exception:
        pass

    # ranked next-moves from the analyzer (top 3)
    try:
        sys.path.insert(0, os.path.join(_engagement.VAULT, "scripts"))
        import next_move
        for m in next_move.suggest(limit=3):
            out.append("  next: " + m)
    except Exception:
        pass

    # harness wordlist: nudge to fold non-obvious routes/params we discovered back in
    try:
        wc = wordlist_candidates()
        if wc and (wc[0] + wc[1]) > 0:
            out.append("  wordlist: %d path + %d param generic candidate(s) -> "
                       "scripts/wordlist-suggest.py, then wl-add.sh" % wc)
    except Exception:
        pass

    # wiki-candidate inbox: nudge review of generic knowledge staged mid-engagement.
    # Silent at 0 (same pattern as the wordlist nag above).
    try:
        wcc = wiki_candidate_count()
        if wcc:
            out.append("  wiki-candidates: %d pending review -> "
                       "scripts/wiki-promote.py --list" % wcc)
    except Exception:
        pass

    # CVE drift: flag when the local nuclei-templates corpus has moved ahead of
    # playbook.json. Gated on the corpus mtime stamp (NOT .wiki-stamp; the corpus
    # is host-local and outside the vault), so this only fires when the corpus
    # actually changed. Best-effort; the corpus may be absent on this device.
    try:
        import cve_feed
        stamp = cve_feed.corpus_stamp()
        if stamp:
            spath = os.path.join(_engagement.VAULT, ".cve-stamp")
            try:
                last = open(spath, encoding="utf-8").read().strip()
            except OSError:
                last = ""
            if stamp != last:
                res = cve_feed.drift()
                if res:
                    total = sum(len(m) for _, _, m in res)
                    out.append(f"CVE drift: {len(res)} fingerprint(s) lag {total} recent "
                               "high/crit CVE(s) -> run `python3 scripts/cve_feed.py --write`, "
                               "review docs/playbook-cve-queue.md, merge into playbook.json.")
                try:
                    open(spath, "w", encoding="utf-8").write(stamp)
                except OSError:
                    pass
    except Exception:
        pass

    # Hook-registration drift: settings.json is machine-local and does not sync,
    # so a vault hook can be silently unregistered on this device. Surface it.
    # Self-contained + best-effort: any failure here must not abort SessionStart.
    try:
        import importlib.util
        _ch_path = os.path.join(_engagement.VAULT, "scripts", "check-hooks.py")
        _spec = importlib.util.spec_from_file_location("check_hooks", _ch_path)
        _ch = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_ch)
        _missing = _ch.missing_hooks()
        if _missing:
            out.append(
                "Hook drift: " + ", ".join(_missing) + " not registered on this "
                "device -> run bash setup/install-hooks.sh")
        _missing_sk = _ch.missing_skills()
        if _missing_sk:
            out.append(
                "Skill drift: " + ", ".join(_missing_sk) + " not registered on "
                "this device -> run bash setup/install-skills.sh")
    except Exception:
        pass

    # Wiki upkeep runs ONLY when wiki/triggers/playbook actually changed since the
    # last session (a cheap stat-only fingerprint vs a stamp). This skips ~4 full
    # wiki walks on every unchanged session - the main SessionStart speedup on the
    # slow Windows mount. When it did change, also nudge a qmd search reindex.
    changed, _ = wiki_changed()
    if changed:
        regen_index()  # keep index.md fresh (idempotent)
        gaps = wiki_gap_count()
        if gaps:
            out.append(f"Wiki gaps: {gaps} technique page(s) referenced but missing "
                       "(run scripts/wiki-gaps.py -v).")
        lint = wiki_lint_summary()
        if lint:
            out.append(lint)
        try:
            import freshness
            fr = freshness.stale()
            if fr:
                out.append(f"Wiki freshness: {len(fr)} reuse page(s) past their refresh window "
                           f"(oldest {fr[0][0]} {fr[0][2]}d) -> run scripts/freshness.py.")
        except Exception:
            pass
        out.append("Wiki changed since last session -> run `qmd update` to refresh the search index.")
        write_stamp(wiki_fingerprint())   # recompute AFTER regen_index bumped index.md, else next session re-fires

    if out:
        print("=== Engagement state ===")
        print("\n".join(out))

    # client narrative loads from the private per-engagement log.md, NOT session/
    # (session/hot.md stays generic/framework-only). log.md = the per-engagement audit;
    # its newest block is the continuity cache surfaced here.
    try:
        rl = _engagement.recent_log()
        if rl:
            print("=== Recent engagement log ===")
            print(rl)
    except Exception:
        pass

    # active research project (raw/research/active.md) surfaces its loop state
    rs = research_status_text()
    if rs:
        print(rs)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
