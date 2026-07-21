#!/usr/bin/env python3
"""UserPromptSubmit hook: auto-fire hunt skills + fire telemetry.

Matches the user prompt against skills/hunt/triggers.json in two tiers and
ROUTES to the relevant skill (surfaces it as a suggestion); the skill itself
carries the methodology mandate, not this hook. Stdout is added to the context.

  - "triggers"         explicit vuln-type keywords -> HIGH confidence.
                       Surface the skill as the relevant one to load.
  - "surface_triggers" natural attack-surface terms (login form, upload field,
                       api endpoint, ...) -> heuristic. Emit a softer "consider"
                       line, escapable when the prompt is not about testing.

De-noise: on a fire we emit ONLY the directive, not the engagement summary
(SessionStart already shows that once) so the action item is not buried.

Telemetry: every prompt (fire or miss) appends one leak-safe record to
<vault>/.trigger-fire.jsonl -- NO prompt text, only ts + fired skills + length.
scripts/trigger-stats.py reads it to measure match rate and tune triggers.json.

Non-fatal: any error exits 0 silent so a broken hook never blocks a prompt.
"""
import json
import os
import re
import sys
import time

# realpath (not abspath) so the symlinked invocation (~/.claude/vault-hooks/...) resolves
# to the real skills/hooks dir -- else tfile below points at a nonexistent path and
# triggers.json never loads, so NO trigger ever fires. Matches _engagement.py.
HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

# Claude Code routes task-notifications (subagent completions) and system reminders
# through UserPromptSubmit too. They are NOT typed user prompts: their text routinely
# quotes vuln keywords (a subagent reporting on SSRF/IDOR/etc.), and routing a hunt
# skill on them misfires. Detect and skip them wholesale -- see the guard at the top of main().
_INJECTED = re.compile(r"<(?:task-notification|system-reminder)\b", re.IGNORECASE)


def _match(patterns, prompt):
    """Return ordered, de-duped skills whose regex key matches the prompt.
    A value may be a string or a list of skills (multi-skill surface)."""
    fired = []
    for pattern, skill in patterns.items():
        try:
            if re.search(pattern, prompt, re.IGNORECASE):
                for s in (skill if isinstance(skill, list) else [skill]):
                    if s not in fired:
                        fired.append(s)
        except re.error:
            continue
    return fired


# Offensive / imperative intent verbs. A hunt-* keyword only earns the MANDATORY
# directive when one of these sits near it; otherwise it is downgraded to the soft
# "consider" tier. Deliberately EXCLUDES past-tense report verbs (found, verified,
# reviewed, noted, mentioned, appears) so tool-output / review prose stays quiet.
_INTENT = re.compile(
    r"\b(?:test(?:s|ing|ed)?|hunt(?:s|ing|ed)?|exploit\w*|attack\w*|pentest\w*|assess\w*|"
    r"probe(?:s|d)?|probing|scan\w*|fuzz\w*|bypass\w*|inject\w*|forge(?:s|d)?|forging|"
    r"tamper\w*|abus\w*|escalat\w*|enumerat\w*|brute\w*|spray\w*|crack\w*|dump\w*|hijack\w*|poison\w*|"
    r"smuggl\w*|travers\w*|overflow\w*|pwn\w*|compromis\w*|reproduc\w*|coerc\w*|craft(?:s|ing|ed)?|"
    r"weaponi\w*|exfiltrat\w*|impersonat\w*|spoof\w*|pivot\w*|replay\w*|"
    r"takeover|take\s+over|look\s+for|search\s+for|attempt\w*)\b",
    re.IGNORECASE)
_INTENT_WINDOW = 64
# a test-stem word DIRECTLY bordering a keyword match (only whitespace between) is part of the
# same noun phrase ("api security testing", "sql injection testing"), NOT an independent intent
# verb. Swallowing it into the masked span stops "document the api security testing methodology"
# from re-satisfying the gate via that trailing "testing". A leading "test " (e.g. "test the api")
# is genuine imperative intent and is left alone.
_ADJ_TEST = re.compile(r"\s+test\w*", re.IGNORECASE)


def _expand_span(text, a, b):
    """Grow keyword span [a,b) to also cover a trailing, directly-adjacent test-stem word."""
    m = _ADJ_TEST.match(text[b:])
    if m:
        b += m.end()
    return a, b


def _match_gated(patterns, text, window=_INTENT_WINDOW):
    """Like _match, but splits hard-tier results into (hard, downgraded).
    A skill goes to `hard` if it is NOT a hunt-* skill, OR a hunt-* skill whose keyword
    match has an intent verb within `window` chars. Otherwise it goes to `downgraded`.

    Intent is searched on a copy of the text with EVERY hard-trigger keyword span blanked
    out, so a keyword that is itself an intent stem (injection / auth bypass / request
    smuggling / forgery / cache poisoning / account takeover) never satisfies the gate --
    not for its own match nor for another keyword's window. Only genuine prose intent counts."""
    hits, spans = [], []
    for pattern, skill in patterns.items():
        try:
            matches = list(re.finditer(pattern, text, re.IGNORECASE))
        except re.error:
            continue
        if matches:
            hits.append((matches, skill))
            spans.extend((m.start(), m.end()) for m in matches)
    hard, downgraded = [], []
    if not hits:
        return hard, downgraded
    masked = list(text)
    for a, b in (_expand_span(text, a, b) for a, b in spans):
        for i in range(a, b):
            masked[i] = " "
    masked = "".join(masked)
    for matches, skill in hits:
        near = any(_INTENT.search(masked[max(0, m.start() - window): m.end() + window])
                   for m in matches)
        for s in (skill if isinstance(skill, list) else [skill]):
            gated = s.startswith("hunt-")
            bucket = hard if (not gated or near) else downgraded
            if s not in bucket:
                bucket.append(s)
    return hard, downgraded


# Strip fenced + inline code before matching so a vuln keyword pasted inside a
# command, grep pattern, or code sample does not fire a MANDATORY hunt directive.
# Prose is untouched. Closed fences first, then a lone unclosed trailing fence
# that BEGINS ITS OWN LINE (a pasted block with no closing ```) -- anchoring to
# line start avoids swallowing prose after a stray mid-sentence backtick-triple,
# then inline `code` spans.
_FENCE = re.compile(r"```[\s\S]*?```|~~~[\s\S]*?~~~")
_FENCE_OPEN = re.compile(r"(?:^|\n)[ \t]*(?:```|~~~)[\s\S]*$")
_INLINE = re.compile(r"`[^`\n]+`")

def _strip_code(text):
    """Return the prompt with fenced and inline code removed (for trigger matching)."""
    text = _FENCE.sub(" ", text)
    text = _FENCE_OPEN.sub(" ", text)
    text = _INLINE.sub(" ", text)
    return text


def _log(vault, hard, soft, nchars):
    """Append a leak-safe fire record. Holds no prompt text (client-data safe)."""
    try:
        rec = {"ts": int(time.time()), "hard": hard, "soft": soft, "n": nchars}
        with open(os.path.join(vault, ".trigger-fire.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def _skills(names):
    return ", ".join("Skill(%s)" % n for n in names)


def main():
    raw = sys.stdin.read()
    try:
        prompt = json.loads(raw).get("prompt", "")
    except Exception:
        prompt = raw  # tolerate non-JSON stdin
    if not prompt:
        return

    # Injected system/tool content is not a real prompt: no fire, no telemetry --
    # a subagent finishing is not a human taking over.
    if _INJECTED.search(prompt):
        return

    tfile = os.path.join(os.path.dirname(HERE), "hunt", "triggers.json")
    try:
        data = json.load(open(tfile, encoding="utf-8"))
    except Exception:
        data = {}
    scan = _strip_code(prompt)
    hard, downgraded = _match_gated(data.get("triggers", {}), scan)
    soft_raw = _match(data.get("surface_triggers", {}), scan) + downgraded
    seen, soft = set(hard), []
    for s in soft_raw:
        if s not in seen:
            seen.add(s); soft.append(s)

    # Framework-meta prompt: a prompt ABOUT the harness itself (documenting the wiki, editing
    # triggers.json, discussing methodology) is not target work -- suppress every fire so it
    # does not route a hunt skill. Logged as a miss below (hard/soft now empty).
    try:
        import _meta
        if _meta.is_prompt_framework_meta(scan):
            hard, soft = [], []
    except Exception:
        pass

    # Locate the vault for telemetry (CLAUDEBRAIN_VAULT override honored via _engagement).
    try:
        import _engagement
        vault = _engagement.VAULT
    except Exception:
        vault = os.path.dirname(os.path.dirname(HERE))
    # Log every prompt -- misses included, so trigger-stats.py shows true match rate.
    _log(vault, hard, soft, len(prompt))

    if not hard and not soft:
        return

    try:
        import _telemetry
        _telemetry.hook("hunt-trigger", tier=("hard" if hard else "soft"))
    except Exception:
        pass

    out = []
    if hard:
        out.append(
            "Relevant skill for this prompt: "
            + _skills(hard)
            + " -- load it before you act on this class; it carries the wiki-first, "
            "tooling-first, and methodology steps. Skip only if it is genuinely irrelevant here."
        )
    if soft:
        out.append(
            "Attack surface matched -- strongly consider loading "
            + _skills(soft)
            + " (heuristic; skip only if this prompt is not about testing that surface)."
        )
    print("\n".join(out))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
