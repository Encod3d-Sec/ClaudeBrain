#!/usr/bin/env python3
"""Stop hook: close-out reflex. When the active engagement is marked SOLVED but its
web evidence is incomplete (a web box with no recon cards or no saved render+source) --
or the walkthrough is not assembled -- or the walkthrough is done but the learn harvest is
still due -- surface a one-line nudge to run the close-out steps. The web-evidence gate
fires FIRST: you cannot have a complete walkthrough without the evidence, and it is the
thing skipped under momentum (recon cards, site render+source).

This is the reflex the de-bloat left unwired: deleting loop-driver removed the Stop-gate,
and _engagement.is_solved / walkthrough_stale / learn_pending had no caller, so a SOLVED box
produced no reminder (observed live: a solved box whose walkthrough + learn were never
invoked). Advisory + fail-open: never blocks the Stop, prints nothing on any
error, and self-clears the moment the walkthrough is assembled and Skill(learn) writes
.learn-done.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def main():
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        return
    if not d:
        return
    # Always-on live capture: fire autocard.sh DETACHED (never blocks the turn, no LLM tokens) to
    # render any scan tmux tab that FINISHED since last turn into recon/. This is the fix for
    # "recon only ever got the rustscan card" - cards now accumulate live, not at close-out.
    try:
        import subprocess
        sc = os.path.join(_engagement.VAULT, "scripts", "autocard.sh")
        if os.path.isfile(sc):
            subprocess.Popen(["bash", sc, os.path.basename(d)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass
    if not _engagement.is_solved(d):
        # During the box: state-discipline reflex. Loot captured but paths.md has no chain
        # rows -> nudge to write the attack path now, not at close-out. Deduped on the loot
        # row-count (a marker) so it re-fires only when a NEW finding lands, never every Stop.
        gap = _engagement.paths_write_gap(d)
        if gap:
            marker = os.path.join(d, ".paths-nudged")
            last = 0
            try:
                last = int((open(marker).read().strip() or "0"))
            except Exception:
                last = 0
            if gap > last:
                print("State-discipline: loot.md has %d finding(s) but paths.md has no chain "
                      "rows. Write the attack path NOW (one row per hop: what -> stage -> "
                      "status) so the chain persists across sessions -- do not defer it to "
                      "close-out." % gap)
                try:
                    open(marker, "w").write(str(gap))
                    import _telemetry
                    _telemetry.drift("close-out", "loot captured but paths.md empty (state discipline)")
                    _telemetry.hook("close-out", action="paths-nudge")
                except Exception:
                    pass
        return
    # box is SOLVED: stamp the finish time once (the far end of the start->finish delta)
    try:
        import _telemetry
        _telemetry.stamp_once("finished_at", _telemetry.now_iso(), d=d)
    except Exception:
        pass
    gaps = _engagement.web_evidence_gaps(d)
    if gaps:
        print("Close-out INCOMPLETE (web box marked SOLVED but evidence missing): "
              + "; ".join(gaps) + ". Capture these NOW so the operator can see/verify what was "
              "found -- do not consider the box done until status.py shows recon-card + source "
              "evidence.")
        return
    if _engagement.walkthrough_stale(d):
        print("Close-out: engagement is SOLVED but walkthrough.md is not assembled. Run "
              "Skill(walkthrough) to build the report from poc/, then Skill(learn).")
    elif _engagement.learn_pending(d):
        print("Close-out: walkthrough assembled, learn harvest still due. Run Skill(learn) "
              "to harvest generic lessons into wiki/ + do the harness retrospective.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
