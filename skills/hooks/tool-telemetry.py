#!/usr/bin/env python3
"""PostToolUse(*) hook: per-box telemetry capture.

For every tool call, appends one event to the active engagement's `.events.jsonl` (the tool
name, plus the skill name for `Skill` calls so skill invocations are countable by name), stamps
`started_at` on the very first event, and records the session `transcript_path` (so token usage
can be attributed to this box later, even across several sessions).

Fail-open and silent: emits nothing, never blocks (PostToolUse can't block a completed call
anyway), no active engagement -> no-op. All aggregation is done offline by scripts/eval_metrics.py.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def main():
    try:
        data = json.loads(sys.stdin.read())
    except Exception:
        return
    tool = data.get("tool_name")
    if not tool:
        return
    try:
        import _telemetry
        import _engagement
    except Exception:
        return
    d = _engagement.active_dir()
    if not d:
        return
    skill = (data.get("tool_input") or {}).get("skill") if tool == "Skill" else None
    _telemetry.log_event("tool", d=d, tool=tool, skill=skill)
    _telemetry.stamp_once("started_at", _telemetry.now_iso(), d=d)
    _telemetry.add_transcript(data.get("transcript_path"), d=d)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
