"""Fail-open telemetry for engagement hooks. Answers, per box:
  - how many skill / hook / tool calls (append-only .events.jsonl)
  - how many drift signals + what triggered them (.events.jsonl kind="drift")
  - tokens per box + start/finish time (.metrics.json + the session transcript paths)

Everything degrades to a no-op on any error: telemetry must never break a tool call or a
hook. The heavy lifting (token attribution, aggregation) lives in scripts/eval_metrics.py,
which reads the two files this module writes; hooks only APPEND cheap events here.
"""
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)


def now_iso():
    """UTC ISO-8601 (comparable to the transcript's ...Z timestamps)."""
    return datetime.now(timezone.utc).isoformat()


def _active(d):
    if d:
        return d
    try:
        import _engagement
        return _engagement.active_dir()
    except Exception:
        return None


def log_event(kind, d=None, **fields):
    """Append one JSON event to the active engagement's .events.jsonl. No engagement -> no-op."""
    try:
        d = _active(d)
        if not d:
            return
        rec = {"ts": now_iso(), "kind": kind}
        rec.update({k: v for k, v in fields.items() if v is not None})
        with open(os.path.join(d, ".events.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def hook(name, d=None, **fields):
    """Record that hook `name` fired (took an action)."""
    log_event("hook", d=d, hook=name, **fields)


def drift(source, reason, d=None):
    """Record an auto-detected drift signal (an enforcement block, a state-discipline nudge,
    a boundary leak-warn). `source` = which guard caught it, `reason` = the one-line trigger."""
    log_event("drift", d=d, source=source, reason=reason)


def _metrics_path(d):
    return os.path.join(d, ".metrics.json")


def _load(d):
    try:
        with open(_metrics_path(d), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _save(d, m):
    try:
        with open(_metrics_path(d), "w", encoding="utf-8") as fh:
            json.dump(m, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass


def stamp_once(key, value, d=None):
    """Set key=value in .metrics.json only if absent/empty. Returns True if newly set."""
    try:
        d = _active(d)
        if not d:
            return False
        m = _load(d)
        if m.get(key):
            return False
        m[key] = value
        _save(d, m)
        return True
    except Exception:
        return False


def stamp(key, value, d=None):
    """Set key=value (overwrite)."""
    try:
        d = _active(d)
        if not d:
            return
        m = _load(d)
        m[key] = value
        _save(d, m)
    except Exception:
        pass


def add_transcript(path, d=None):
    """Record a session transcript path in .metrics.json (for later token attribution).
    A box spanning several sessions accumulates all the transcripts that touched it."""
    try:
        if not path:
            return
        d = _active(d)
        if not d:
            return
        m = _load(d)
        seen = m.get("transcripts", [])
        if path not in seen:
            seen.append(path)
            m["transcripts"] = seen
            _save(d, m)
    except Exception:
        pass
