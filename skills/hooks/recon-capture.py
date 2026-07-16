#!/usr/bin/env python3
"""PostToolUse(Bash) hook: fingerprint auto-router + OOB callback correlation.

Two jobs after a recon/exec tool runs:
  1. Fingerprint router: match scripts/playbook.json tech fingerprints against the
     command AND its output, and inject the matching "<tech> detected -> load Skill(x)"
     routing line. This auto-fires the hunt skill the moment tech is discovered,
     instead of waiting for the next SessionStart next-move pass. A framework-meta
     guard suppresses false fires when the command is reading/editing the vault's own
     playbook/hook/wiring machinery (its output is full of playbook tokens).
  2. OOB callback auto-correlation: flip a waiting oob.md row to HIT when its planted
     token appears in the command+output blob (operator polling OAST/Collaborator).

Keyword matching only (no structured/version-fragile parsing).
Emits Claude Code JSON additionalContext. Non-fatal: any error exits 0 silent.
"""
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# tools that produce host/service/asset intel
RECON_TOOLS = (r"nmap|masscan|nxc|netexec|crackmapexec|cme|ffuf|httpx|subfinder|rustscan|"
               r"naabu|dnsx|katana|gau|amass|gowitness|arjun|nuclei|gobuster|feroxbuster")
# tools that produce credentials/secrets
CRED_TOOLS = (r"secretsdump|getuserspns|getnpusers|gettgt|certipy|kerbrute|hashcat|john|"
              r"lsassy|nanodump|trufflehog|gitleaks")
# commands whose output is worth fingerprinting (discovery/probes/testers)
PROBE_TOOLS = RECON_TOOLS + r"|curl|wget|whatweb|wpscan|nikto|whatwaf|nslookup|dig|sqlmap|dalfox|swaks"

MAX_BLOB = 20000   # cap output scanned for fingerprints
MAX_HITS = 3


# hunt-<x> skill -> wiki/payloads/<file>.md. Most map by stripping "hunt-"; the alias
# map covers the names that differ from the payload filename.
_PAYLOAD_ALIAS = {
    "auth": "auth-bypass", "injection": "ssti", "upload": "file-upload",
    "cache": "web-cache", "cloud": "imds-cloud-metadata", "rce": "command-injection",
    "federation": "oauth-saml", "m365": "oauth-saml", "bizlogic": "race-conditions",
    "llm": "llm-prompt-injection", "ics": "modbus",
}


def _payload_page(skill):
    """Relative wiki/payloads path for a hunt skill, or None if no arsenal file exists."""
    try:
        base = skill[5:] if skill.startswith("hunt-") else skill
        name = _PAYLOAD_ALIAS.get(base, base)
        import _engagement
        rel = os.path.join("wiki", "payloads", name + ".md")
        if os.path.exists(os.path.join(_engagement.VAULT, rel)):
            return rel
    except Exception:
        pass
    return None


def _label_payload_pages(label):
    """wiki/payloads pages whose filename exactly matches an alnum token (>=3 chars) in
    the fingerprint label. Catches specific sub-classes the coarse skill->payload map
    misses (graphql/jwt/ldap/xxe/nosql/xpath/cors/csrf/...). Existence-guarded."""
    out = []
    try:
        import _engagement
        for tok in re.findall(r"[a-z0-9]{3,}", (label or "").lower()):
            rel = os.path.join("wiki", "payloads", tok + ".md")
            if rel not in out and os.path.exists(os.path.join(_engagement.VAULT, rel)):
                out.append(rel)
    except Exception:
        pass
    return out


# tool-name -> tools/ page basename, where the invoked binary differs from the page
_TOOL_ALIAS = {"crackmapexec": "netexec", "cme": "netexec"}


def _tool_page(tool):
    """Relative wiki/tools path for a tool name (alias-aware), or None."""
    if not tool:
        return None
    name = _TOOL_ALIAS.get(tool.lower(), tool.lower())
    try:
        import _engagement
        rel = os.path.join("wiki", "tools", name + ".md")
        if os.path.exists(os.path.join(_engagement.VAULT, rel)):
            return rel
    except Exception:
        pass
    return None


# leading wrappers/env-assignments to strip before checking a segment's command
_WRAP = re.compile(r"^(sudo|env|time|timeout|nice|nohup|stdbuf|doas|proxychains4?)\b", re.I)
_ASSIGN = re.compile(r"^\w+=\S*")
_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")


def _blank_quotes(s):
    """Blank single/double-quoted spans (length-preserving) so shell operators and tool
    names INSIDE quotes are inert -- e.g. a `grep -E 'a|b|kerbrute'` pattern must not be
    split on its `|` alternation, nor have `kerbrute` read as an invoked command."""
    return _QUOTED.sub(lambda m: " " * len(m.group(0)), s)


def invokes(cmd, tools):
    """Return a match for a tool that is actually INVOKED (a segment's command), not merely
    mentioned as a path/argument or inside a quoted pattern. Blanks quoted spans, splits on
    ; | && || newline, strips sudo/env/timeout-style wrappers, then checks the first token
    of each segment. Avoids false fires like `ls /root/nuclei-templates`, `find . -name
    nuclei`, or `grep -E 'a|nuclei|kerbrute' f` (quoted alternation, the recurring one)."""
    rx = re.compile(r"^(" + tools + r")\b", re.IGNORECASE)
    for seg in re.split(r"&&|\|\||[;|\n]", _blank_quotes(cmd)):
        toks = seg.strip()
        prev = None
        while toks and toks != prev:   # peel wrappers/env-assignments/their args
            prev = toks
            m = _ASSIGN.match(toks)
            if m:
                toks = toks[m.end():].lstrip()
                continue
            w = _WRAP.match(toks)
            if w:
                toks = toks[w.end():].lstrip()
                toks = re.sub(r"^((-{1,2}\S+|\d+)\s+)*", "", toks)  # drop flags / timeout's secs
        m = rx.match(toks)
        if m:
            return m
    return None


# Bridge wrappers: this harness runs remote tooling via `bash /root/vm.sh '<cmd>'`,
# `sshpass ... ssh user@host '<cmd>'`, or `wsl ... -- <cmd>`. The real tool sits inside
# the wrapper's quoted arg, so invokes() (command-position) misses it. Extract the inner
# command(s) so the caller can run invokes()/fingerprinting against them too.
#
# Also unwraps two more shapes: a `-c`/`-e` code-exec payload (python3/node/bash/sh/perl/
# ruby/deno '<payload>') and a heredoc body. Both recurse so a wrapper NESTED inside one of
# these (e.g. vm.sh called from inside a `bash -c` body) still gets unwrapped too.
_CODE_C_RE = re.compile(
    r"^(?:\S*/)?(?:python3?|node|bash|sh|perl|ruby|deno)\s+-[ce]\s+(['\"])(.+)\1\s*$", re.S)
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1\s*\n(.*?)\n\s*\2\b", re.S)
_LOOP_PREFIX = re.compile(r"^(?:do|then|;)\s+", re.I)


def _segments(c):
    """Split c on ;|&&|\\|\\|/newline/pipe boundaries that are OUTSIDE quoted spans,
    returning the ORIGINAL (un-blanked) segment strings so a quoted URL/cookie survives.
    _blank_quotes is length-preserving, so split offsets computed on the blanked copy
    apply verbatim to the original."""
    blanked = _blank_quotes(c or "")
    out, last = [], 0
    for m in re.finditer(r"&&|\|\||[;|\n]", blanked):
        out.append((c or "")[last:m.start()])
        last = m.end()
    out.append((c or "")[last:])
    return out


def inner_cmds(cmd):
    """Inner remote command strings pulled out of vm.sh / ssh / wsl wrappers, a -c/-e
    code-exec payload, or a heredoc body ([] if none). Command-position anchored for the
    bridge wrappers: extracts only when the wrapper is actually invoked (first token of a
    ;|&&-split segment, after peeling sudo/env/timeout and a leading for/while/if loop-body
    keyword `do `/`then `), not merely quoted inside another command's argument."""
    inners = []
    # heredoc body: pulled from the WHOLE command first -- the per-segment split below
    # would shred a multi-line heredoc body across several bogus segments before this ever
    # got a chance to see it whole.
    for m in _HEREDOC_RE.finditer(cmd):
        body = m.group(3)
        inners.append(body)
        inners.extend(inner_cmds(body))
    # quote-aware split: a raw ;/|/&&/||/newline split shreds a wrapper's quoted arg when
    # that arg itself contains one of these separators (e.g. vm.sh 'C=x; curl ... | grep
    # ...'). _segments() splits on the same separator set but only OUTSIDE quoted spans.
    for seg in _segments(cmd):
        toks = seg.strip()
        toks = _LOOP_PREFIX.sub("", toks)     # a for/while/if loop's `do ...`/`then ...` body
        prev = None
        while toks and toks != prev:          # peel sudo/env/timeout + their args (same as invokes)
            prev = toks
            m = _ASSIGN.match(toks)
            if m:
                toks = toks[m.end():].lstrip()
                continue
            w = _WRAP.match(toks)
            if w:
                toks = toks[w.end():].lstrip()
                toks = re.sub(r"^((-{1,2}\S+|\d+)\s+)*", "", toks)
        # -c / -e code-exec payload: recurse so a wrapper nested inside it still unwraps.
        m = _CODE_C_RE.match(toks)
        if m:
            inner = m.group(2)
            inners.append(inner)
            inners.extend(inner_cmds(inner))
            continue
        # vm.sh:  [bash ]<path>vm.sh '<cmd>'
        m = re.match(r"(?:bash\s+)?\S*vm\.sh\s+(['\"])(.+?)\1", toks, re.S)
        if m:
            inners.append(m.group(2)); continue
        # ssh:    [sshpass ...] ssh [opts] user@host '<cmd>'
        m = re.match(r"(?:sshpass\b.*?\s)?ssh\b[^\n]*?\s\S+@\S+\s+(['\"])(.+?)\1", toks, re.S)
        if m:
            inners.append(m.group(2)); continue
        # wsl:    wsl [...] -- <cmd>
        m = re.match(r"wsl\b.*?\s--\s+(.+)", toks, re.S)
        if m:
            inners.append(m.group(1).strip()); continue
    return inners


def _response_text(data):
    r = data.get("tool_response")
    if r is None:
        return ""
    if isinstance(r, str):
        return r
    try:
        return json.dumps(r)[:MAX_BLOB]
    except Exception:
        return str(r)[:MAX_BLOB]


def fingerprint_records(blob):
    """Return up to MAX_HITS (label, spec) tuples matched from playbook.json. The label is
    the cleaned first fingerprint token; spec is the raw playbook record (skills/tools/refs/
    tests). Backs the routing display (fingerprint_hits)."""
    try:
        import _engagement
        pb = os.path.join(_engagement.VAULT, "scripts", "playbook.json")
        fps = json.load(open(pb, encoding="utf-8"))["fingerprints"]
    except Exception:
        return []
    out = []
    for key, spec in fps.items():
        try:
            if not re.search(key, blob, re.IGNORECASE):
                continue
        except re.error:
            continue
        label = key.split("|")[0].replace("\\b", "")   # clean regex tokens for display
        out.append((label, spec))
        if len(out) >= MAX_HITS:
            break
    return out


def fingerprint_hits(blob):
    """Return up to MAX_HITS ROUTING lines ('<tech> detected -> load Skill(x)') from
    playbook.json. Routing only: the named hunt skill owns the tests, tooling-first,
    payload arsenal, and cheatsheet reuse -- this hook surfaces the skill, it does not
    prescribe methodology."""
    out = []
    for label, spec in fingerprint_records(blob):
        skills = spec.get("skills") or []
        sk = (" -> load " + ", ".join("Skill(%s)" % s for s in skills)) if skills else ""
        out.append(f"  {label} detected{sk}")
    return out


# Framework-meta guard: a command that reads/edits the vault's OWN wiring/hook/playbook
# machinery is NOT target recon. Its output is full of playbook tokens (hunt-<class> skill
# names, fingerprint regexes, payload/technique page names) that would otherwise false-match
# the fingerprint router and get surfaced as a "discovered surface" (observed live: editing
# playbook.json / running apply-wiring falsely fingerprinted as deserialization/sqli). These
# tokens never appear in genuine target recon, so a plain presence check on the command is safe.
_FRAMEWORK_META = re.compile(
    r"playbook\.json|triggers\.json|wiki-wiring|apply-wiring|wiring-exempt|"
    r"recon-capture|loop-driver|hunt-trigger|scope-guard|engagement-init|"
    r"scripts/(?:playbook|wiki|gen_index|build_moc|wl-add|wiki-stage|check-hooks)|"
    r"skills/hooks|/vault-hooks/", re.IGNORECASE)


def _is_framework_meta(cmd):
    """True if the command operates on the vault's own framework machinery (playbook/hooks/
    wiki-wiring), so the fingerprint router must NOT treat its output as target recon."""
    return bool(_FRAMEWORK_META.search(cmd or ""))


def _emit(blocks):
    if not blocks:
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n\n".join(blocks),
        }
    }))


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd:
        return

    # active engagement dir (used by the OOB correlation)
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        _engagement = None
        d = None

    # Skip pure documentation/discussion commands (a comment, echo, a cat/grep/rg of some
    # file): they never invoke a probe tool, so there is nothing to fingerprint.
    if re.match(r"\s*(#|echo\b|printf\b|cat\b|grep\b|rg\b)", cmd, re.IGNORECASE):
        return

    blocks = []

    # 0. OOB callback auto-correlation: flip a waiting oob.md row to HIT when its
    #    token label appears in this command's output (operator polling OAST/Collaborator).
    if d and _engagement:
        blob_oob = cmd + "\n" + _response_text(data)
        flipped = []
        for row in _engagement.oob_rows(d):
            if row.get("status", "").strip().lower() not in ("waiting", ""):
                continue
            token = (row.get("token", "") or "").strip()
            if token and len(token) >= 4 and token in blob_oob:
                if _engagement.flip_oob_status(d, token, "HIT",
                                               source="callback " + time.strftime("%Y-%m-%d")):
                    flipped.append(row.get("sink", token) or token)
        if flipped:
            blocks.append(
                "OOB HIT auto-correlated -- callback landed for: " + "; ".join(flipped[:4])
                + ". Gate passed: scaffold + validate the FIND now (oob.md row is HIT)."
            )

    # 1. fingerprint router (runs on any discovery/probe command; engagement-agnostic).
    #    command-position match: the tool must be invoked, not just named in a path/arg.
    #    Also check inside vm.sh/ssh/wsl bridge wrappers, where the real tool sits inside a
    #    quoted inner command that invokes() alone (outer cmd only) would miss.
    #    Skip framework-meta commands: editing/reading the vault's own playbook/wiki/hooks
    #    emits playbook tokens that would false-fingerprint as a discovered surface.
    _inners = inner_cmds(cmd)
    is_probe = invokes(cmd, PROBE_TOOLS) or next(
        (m for ic in _inners if (m := invokes(ic, PROBE_TOOLS))), None)
    if is_probe and not _is_framework_meta(cmd):
        blob = (cmd + "\n" + _response_text(data))[:MAX_BLOB]
        recs = fingerprint_records(blob)
        if recs:
            skills_lines = []
            for label, spec in recs:
                sk = spec.get("skills") or []
                tail = (" -> load " + ", ".join("Skill(%s)" % s for s in sk)) if sk else ""
                skills_lines.append("  %s detected%s" % (label, tail))
            blocks.append(
                "Tech fingerprinted (playbook.json) -> load the hunt Skill named below; it "
                "carries the wiki-first, tooling-first, tests, and payload steps:\n"
                + "\n".join(skills_lines)
            )

    _emit(blocks)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
