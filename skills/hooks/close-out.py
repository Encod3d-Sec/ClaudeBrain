#!/usr/bin/env python3
"""Stop hook: close-out reflex. When the active engagement is marked SOLVED but its
walkthrough is not assembled -- or the walkthrough is done but the learn harvest is still
due -- surface a one-line nudge to run the close-out skills.

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
    if not d or not _engagement.is_solved(d):
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
