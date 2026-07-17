#!/usr/bin/env python3
"""next_move.py - rank the next offensive moves from engagement state.

Read-only analyzer. Reads the active engagement's state/loot/paths tables and
applies internal-pentest heuristics to produce a ranked, deduped list of
actionable moves. Deterministic + cheap (no model tokens). The model elaborates
on demand via the `next-move` skill; the SessionStart hook surfaces the top few.

Also emits low-ranked [gap] floor moves for untested vuln classes (the per-type
checklist in coverage-classes.json minus classes auto-credited as tested from
the killchain.md 4a table + written findings + Deadends.md), so systematic breadth
reaches the shortlist even when nothing was fingerprinted. Skill(coverage) has the
full per-asset matrix; these are just the "don't forget class X" nudge.

CLI:  python3 scripts/next_move.py [-v]
API:  next_move.suggest(limit=5) -> list[str]
"""
import json
import os
import re
import sys

# self-locate vault, reuse the hooks' table parser
VAULT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
sys.path.insert(0, os.path.join(VAULT, "skills", "hooks"))
import _engagement  # noqa: E402

_PB_PATH = os.path.join(VAULT, "scripts", "playbook.json")
try:
    PLAYBOOK = json.load(open(_PB_PATH, encoding="utf-8"))["fingerprints"]
except FileNotFoundError:
    PLAYBOOK = {}   # absent (e.g. fresh clone) -> silent, fingerprint moves just off
except Exception as _e:
    PLAYBOOK = {}
    sys.stderr.write(f"next_move: playbook.json unreadable ({_e}); fingerprint moves disabled\n")

_CC_PATH = os.path.join(VAULT, "scripts", "coverage-classes.json")
try:
    CLASSES = json.load(open(_CC_PATH, encoding="utf-8"))
except Exception:
    CLASSES = {}   # absent/unreadable -> coverage-gap moves just off

DEAD = ("dead", "done")
HIGH_VALUE_SVC = ("mssql", "winrm", "smb", "ssh", "rdp", "ldap", "kerberos")
# which access values mean "reachable, go get a foothold" per engagement type
ACQUIRE_ACCESS = {
    "pentest": ("port-open", "creds-partial"),
    "ctf": ("port-open",),
    "bugbounty": ("recon", "tested"),
}
ACQUIRE_VERB = {"pentest": "acquire creds", "ctf": "get foothold", "bugbounty": "test"}
def _norm_key(text):
    """Dedup key: full normalized token string. Collapses only true duplicates
    (distinct hosts/paths/creds stay separate). Relay path-vs-note redundancy is
    handled upstream via the already_relay flag, not here."""
    toks = "".join(c if c.isalnum() or c.isspace() else " " for c in text.lower()).split()
    return " ".join(toks)


def _ranked(limit=5):
    """Core ranking: list of (score, tag, text) tuples, highest first, capped at
    limit. None when there is no active engagement. suggest()/suggest_json() wrap it."""
    d = _engagement.active_dir()
    if not d:
        return None
    etype = _engagement.engagement_type(d)
    sc = _engagement.scope(d)
    state = _engagement._parse_table(os.path.join(d, "state.md"))
    loot = _engagement._parse_table(os.path.join(d, "loot.md"))
    paths = _engagement._parse_table(os.path.join(d, "paths.md"))

    sugg = []  # (score, tag, text)

    def entity(r):
        return _engagement.entity(r, etype)

    def in_scope(r):
        return not _engagement.out_of_scope_match(entity(r), sc)

    # 1. open paths - directly actionable (all engagement types)
    for r in paths:
        if r.get("status", "").lower() == "open":
            mv = r.get("next-move") or r.get("stage", "")
            sugg.append((100, "now", f"{r.get('path', '?')} - {mv}"))

    # RoE: passive-only forbids active probing/cred work; no_bruteforce forbids spray
    passive = sc.get("passive_only")
    no_brute = sc.get("no_bruteforce")

    # 1b. fingerprint-driven tests: match tech/services -> targeted tests (top 4)
    if not passive and PLAYBOOK:
        seen = set()
        tests = []
        for r in state:
            if not in_scope(r):
                continue
            # split the match surface: structured columns = high confidence,
            # free-text (os/notes) = low confidence (used only as a sort tiebreak)
            structured = " ".join(str(r.get(k, "")) for k in ("tech", "services", "service")).lower()
            freetext = " ".join(str(r.get(k, "")) for k in ("os", "notes")).lower()
            ent = entity(r)
            for pat, info in PLAYBOOK.items():
                try:
                    hi = bool(re.search(pat, structured))
                    lo = bool(re.search(pat, freetext))
                except re.error:
                    continue
                if not (hi or lo):
                    continue
                if (ent, pat) in seen:
                    continue
                seen.add((ent, pat))
                try:
                    prio = max(1, min(3, int(info.get("prio", 2))))
                except (TypeError, ValueError):
                    prio = 2
                score = 80 + prio * 5            # prio 1/2/3 -> 85/90/95
                appr = info.get("approach")      # engagement-type tuning (ctf/bugbounty/pentest)
                if appr:                          # surface on-approach fingerprints first;
                    score += 6 if etype in appr else -4   # off-approach still shown, just lower
                conf = 1 if hi else 0            # structured match outranks a notes-only match
                tlist = ", ".join(info.get("tests", [])[:3])
                sk = " [" + ",".join(info["skills"]) + "]" if info.get("skills") else ""
                flag = "" if conf else " (low-confidence: matched notes/os)"
                tests.append((score, conf, f"{ent}: {tlist}{sk}{flag}"))
        # sort by score then confidence BEFORE the cap, so a critical fingerprint is
        # never silently truncated below an info-level one by dict-insertion order
        tests.sort(key=lambda t: (-t[0], -t[1]))
        sugg.extend((s, "test", text) for s, c, text in tests[:4])

    # 2+3. pentest-only: cred reuse spray + relay posture (AD-specific)
    if etype == "pentest" and not passive:
        usable = [c for c in loot if c.get("status", "").lower() == "active"]
        if not no_brute:
            for c in usable:
                cred = c.get("cred", "?")
                reused = (c.get("reused-where", "") or "").lower()
                tgts = [r.get("host", "?") for r in state
                        if r.get("access", "") not in ("none", "")
                        and r.get("host", "").lower() not in reused and in_scope(r)]
                if tgts:
                    sugg.append((90, "now", f"spray {cred} at {', '.join(tgts[:6])}"
                                 + (" ..." if len(tgts) > 6 else "")))
        signing_false = [r for r in state if r.get("signing", "").strip().lower() in ("false", "no", "disabled", "off") and in_scope(r)]
        if signing_false:
            n = len(signing_false)
            already = any("relay" in t.lower() for _, _, t in sugg)
            if usable and not no_brute and not already:
                sugg.append((95, "now", f"relay-ready: {n} signing:False host(s), spray-relay a usable cred"))
            elif not usable and not already:
                sugg.append((60, "blocked", f"relay blocked: need 1 valid cred first; {n} signing:False host(s) ready"))

    # 4. acquisition - reachable entities with no foothold yet (type-aware).
    #    Suppressed under passive-only. Out-of-scope entities filtered. Cap 3.
    if not passive:
        verb = ACQUIRE_VERB.get(etype, "acquire creds")
        acc_set = ACQUIRE_ACCESS.get(etype, ("port-open", "creds-partial"))
        acq = []
        for r in state:
            if r.get("access", "") not in acc_set or not in_scope(r):
                continue
            ent = entity(r)
            svc = r.get("services", "") or r.get("tech", "") or r.get("service", "")
            hv = any(k in svc.lower() for k in HIGH_VALUE_SVC)
            score = 70 if r.get("access") in ("creds-partial", "tested") else (55 if hv else 30)
            note = r.get("notes", "")
            detail = f" ({note})" if note else (f" ({svc})" if svc else "")
            acq.append((score, "acquire", f"{verb}: {ent}{detail}"))
        sugg.extend(sorted(acq, key=lambda x: -x[0])[:3])

    # 4b. coverage-gap floor: untested base vuln classes (per-type checklist in
    #     coverage-classes.json, ordered high-to-low impact) minus whatever the killchain.md
    #     4a table records as tested anywhere. Ranked BELOW every concrete move (scores 24-28,
    #     under the acquisition floor of 30), so a gap never displaces a real lead but
    #     systematic breadth still reaches the shortlist when no fingerprint matched.
    #     Skill(coverage) holds the per-asset matrix; this is only the "test class X"
    #     nudge. Suppressed under passive_only (active testing forbidden).
    if not passive and any(in_scope(r) and entity(r) != "?" for r in state):
        base = CLASSES.get(etype, [])
        try:
            per_asset, glob = _engagement.tested_classes(d, etype, base)
        except Exception:
            per_asset, glob = {}, set()
        tested_any = {t.lower() for t in glob}
        for s in per_asset.values():
            tested_any |= {t.lower() for t in s}
        untested = [c for c in base if c.lower() not in tested_any]
        for i, cls in enumerate(untested[:5]):        # cap: shortlist, not the full matrix
            sugg.append((28 - i, "gap",
                         f"{cls}: untested vuln class (Skill(coverage) for per-asset gaps)"))

    # 5. blocked paths - surface unblock hint
    for r in paths:
        if r.get("status", "").lower() == "blocked":
            path = r.get("path", "?")
            blk = r.get("blocker", "")
            mv = r.get("next-move", "")
            sugg.append((40, "blocked", f"{path} - {blk} -> {mv}"))

    # dead/done already excluded by only reading open/blocked/reachable above.

    # dedup by loose key, keep highest score
    best = {}
    for score, tag, text in sugg:
        k = _norm_key(text)
        if k not in best or score > best[k][0]:
            best[k] = (score, tag, text)
    ranked = sorted(best.values(), key=lambda x: -x[0])
    return ranked[:limit]


def suggest(limit=5):
    """Top moves as display strings. Stable string contract - many callers + tests
    depend on it; do not change the shape here."""
    ranked = _ranked(limit)
    if ranked is None:
        return []
    return ([f"[{tag}] {text}" for _, tag, text in ranked]
            or ["No open moves. Recon more hosts or capture a cred."])


def suggest_json(limit=5):
    """Same ranking as suggest(), as structured dicts (score/tag/text) so the
    next-move skill can run a model re-rank pass over the deterministic order.
    [] when there is no engagement or no open moves."""
    ranked = _ranked(limit)
    return [{"score": s, "tag": t, "text": x} for s, t, x in (ranked or [])]


def main():
    if "--json" in sys.argv:   # structured candidates for the next-move skill's re-rank
        print(json.dumps(suggest_json(limit=999 if "-v" in sys.argv else 8)))
        return
    limit = 999 if "-v" in sys.argv else 5
    moves = suggest(limit=limit)
    d = _engagement.active_dir()
    name = os.path.basename(d) if d else "?"
    print(f"Next moves ({name}):")
    for i, m in enumerate(moves, 1):
        print(f" {i}. {m}")


if __name__ == "__main__":
    main()
