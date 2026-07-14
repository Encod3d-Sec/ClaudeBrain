#!/usr/bin/env python3
"""PostToolUse(Bash) hook: capture nudge + fingerprint auto-router.

Two jobs after a recon/exec tool runs:
  1. Capture nudge: if engagement state files were not touched recently, remind
     the model to extract results into state.md / loot.md.
  2. Fingerprint router: match scripts/playbook.json tech fingerprints against
     the command AND its output, and inject the matching targeted tests + hunt
     skill. This auto-fires the test engine the moment tech is discovered,
     instead of waiting for the next SessionStart next-move pass.

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

STALE_SECONDS = 300
RENDER_TIMEOUT = 22   # bounded synchronous lead-card render budget (seconds); see stage_req_resp call site

# tools that produce host/service/asset intel -> state.md
RECON_TOOLS = (r"nmap|masscan|nxc|netexec|crackmapexec|cme|ffuf|httpx|subfinder|rustscan|"
               r"naabu|dnsx|katana|gau|amass|gowitness|arjun|nuclei|gobuster|feroxbuster")
# tools that produce credentials/secrets -> loot.md
CRED_TOOLS = (r"secretsdump|getuserspns|getnpusers|gettgt|certipy|kerbrute|hashcat|john|"
              r"lsassy|nanodump|trufflehog|gitleaks")
# commands whose output is worth fingerprinting (discovery/probes/testers)
PROBE_TOOLS = RECON_TOOLS + r"|curl|wget|whatweb|wpscan|nikto|whatwaf|nslookup|dig|sqlmap|dalfox|swaks"
# CVE-research tools -> nudge research-loop capture (findings.md / loop.md)
RESEARCH_TOOLS = r"afl-fuzz|aflplusplus|afl-clang|libfuzzer|-fsanitize=fuzzer|semgrep|codeql|trivy|grype|\bangr\b|ghidra|analyzeHeadless|bindiff|diaphora|\bgdb\b|pwndbg|objdump|\bfrida\b|valgrind"
# shot-worthy tools. Matched at COMMAND POSITION (via invokes()/inner_cmds below), not
# a loose whole-command search: a poll loop / grep / cd / echo that merely MENTIONS the
# tool name (e.g. `grep NMAP-DONE`, `cd /opt/nmap-scripts`) must NOT stage a spurious card.
_SHOT_NET_TOOLS = (r"nmap|masscan|naabu|rustscan|ffuf|feroxbuster|gobuster|nuclei|"
                   r"nxc|netexec|crackmapexec|whatweb|nikto")
# privesc scripts run path-prefixed (./linpeas.sh, /tmp/pspy64) -> command-position + path
_SHOT_SCRIPT_CMD = re.compile(r"^(?:\S*/)?(linpeas|winpeas|pspy)\w*", re.I)
_LEAD_WRAP = re.compile(r"^(?:sudo|env|time|timeout|nice|ionice|nohup|stdbuf|doas|proxychains4?)\b\s+"
                        r"(?:-{1,2}\S+\s+|\d+\s+)*", re.I)


def _shot_tool(cmd):
    """(tool, title) for a shot-tool INVOKED at command position by cmd (vm.sh/ssh/wsl
    wrapper tolerant), or None. Command-position so a poll loop / grep / cd / echo that
    merely MENTIONS the tool name does not stage a card. title = the tool command run."""
    for c in [cmd] + inner_cmds(cmd):
        m = invokes(c, _SHOT_NET_TOOLS)                     # network tools (quote/wrapper safe)
        tool = m.group(1).lower() if m else None
        if not tool:                                         # privesc scripts (path-prefixed)
            for seg in re.split(r"&&|\|\||[;|\n]", _blank_quotes(c)):
                ms = _SHOT_SCRIPT_CMD.match(_LEAD_WRAP.sub("", seg.strip()))
                if ms:
                    tool = ms.group(1).lower()
                    break
        if tool:
            m2 = re.search(r"((?:\S*/)?%s\b[^\n;]*)" % tool, c, re.I)
            title = (m2.group(1) if m2 else c.splitlines()[0]).strip()[:200]
            return tool, title
    return None
MAX_BLOB = 20000   # cap output scanned for fingerprints
MAX_HITS = 3

# HTTP request tools whose RESPONSE we auto-card when it shows a lead (curl/wget). Kept
# separate from the scan-tool staging (_SHOT_NET_TOOLS) -- those card the tool run; this
# cards the request+response the moment a lead lands.
_REQ_TOOLS = r"curl|wget"
# Lead signals in a response: a credential/key/flag/leaked-source/config. High-confidence set
# (a login FORM's name="password" has no following [:=], so it won't false-fire). reqshot is
# the full-fidelity path; this is the automatic net so no lead is missed while exploiting.
_LEAD_RE = re.compile(
    r"THM\{|FLAG\{|flag\{|HTB\{|CTF\{"                                    # flags
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"            # private keys
    r"|AKIA[0-9A-Z]{16}"                                                  # AWS access key id
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."                         # JWT
    r"|(?:password|passwd|api[_-]?key|secret|access[_-]?token|db_pass\w*|private[_-]?key|mnemonic)"
    r"[\"'\s]{0,3}[:=][\"'\s]{0,3}\S"                                     # key = value (incl. leaked wallet key)
    r"|<\?php\b|-----BEGIN CERTIFICATE|<title>\s*Index of|\bIndex of /"   # leaked source / dir listing
    r"|root:[^:\n]*:0:0:",                                                # /etc/passwd row
    re.I)

# Finding-landed signals for the screenshot-on-finding reflex. Kept NARROW on purpose -- a
# captured flag, or a shell/privesc `id` landing -- so the nudge fires on an unambiguous SUCCESS,
# not on any "password:"-shaped string in a page body (that is what _LEAD_RE catches for the
# request auto-card; this reflex prompts the DELIBERATE visual state instead). thm_biblioteca gap:
# Skill(screenshot) was only called at the very end, so transient finding states were never shot.
_FINDING_RE = re.compile(
    r"THM\{|FLAG\{|flag\{|HTB\{|CTF\{"                 # a flag was read
    r"|uid=\d+\([a-z_][^)]*\)\s*gid=",                  # `id` output = a shell / privesc landing
    re.I)

# Content-discovery tools -- for the recon-completeness reflex (did we ever fuzz for routes?).
_DISCOVERY_TOOLS = r"ffuf|feroxbuster|gobuster|dirb|dirsearch"


def is_lead(output):
    """True if a response body carries a lead signal (cred/key/flag/leaked source)."""
    return bool(output) and bool(_LEAD_RE.search(output[:MAX_BLOB]))


# Listener tools: a flag/cookie/cred can land on THEIR stdout (an XSS beacon calling back
# to a listener, not a curl/wget response) -- this is the exact thm_sequence blind spot
# (root cause #1). nc/ncat require a listen flag (-l) so an ordinary outbound `nc host port`
# client connection is not mistaken for a listener.
_LISTENER_RE = re.compile(
    r"\b(?:nc|ncat)\b[^\n;&|]*-\w*l"           # nc/ncat ... -l (any combined flag with l)
    r"|\bpython3?\s+-m\s+http\.server\b"
    r"|\bsocat\b",
    re.I)


def is_listener(cmd):
    """True if cmd invokes a listener tool (nc -l / ncat -l / python3 -m http.server /
    socat) -- a surface the curl/wget-only lead-net (_REQ_TOOLS) cannot see on its own."""
    return bool(_LISTENER_RE.search(cmd or ""))


# per-host hand-curl repetition counter: a single ad-hoc curl is fine, but repeatedly
# hand-curling the SAME in-scope host within a session is the genuine "reimplementing a
# tool" signal -> nudge httpx/ffuf/nuclei. Persisted in targets/<eng>/.curl-counts.json.
# Suppressed under tunnel_safe (curl+nc is correct when scanners kill the pivot).
CURL_REPEAT_THRESHOLD = 4
_URL_HOST = re.compile(r"https?://([^/\s'\"]+)", re.I)


def _probe_host(cmd):
    """Lowercased hostname (userinfo and port stripped) of the first http(s) URL in cmd,
    or None. Substring search so a curl wrapped in vm.sh/ssh still yields its target."""
    m = _URL_HOST.search(cmd or "")
    if not m:
        return None
    host = m.group(1).split("@")[-1].split(":")[0].strip().lower()
    return host or None


def _in_scope(host, sc):
    """True if host matches any in-scope entry, via the boundary-aware matcher in
    strict mode (exact/parent-domain/CIDR only). Empty in_scope -> False. strict=True
    because this gates writing a response body to disk; a spoofable label-prefix match
    (anyone can register <label>.attacker.tld) must not authorize that."""
    if not host:
        return False
    try:
        import _engagement
        return any(_engagement._scope_entry_match(host, (o or "").lower().strip(), strict=True)
                   for o in sc.get("in_scope", []))
    except Exception:
        return False


def _bump_curl_count(d, host):
    """Increment and persist the per-host hand-curl count in .curl-counts.json. Returns the
    new count, or 0 on any error. Best-effort; never raises."""
    p = os.path.join(d, ".curl-counts.json")
    try:
        counts = json.loads(open(p, encoding="utf-8").read() or "{}")
        if not isinstance(counts, dict):
            counts = {}
    except Exception:
        counts = {}
    try:
        n = int(counts.get(host, 0) or 0) + 1
    except (TypeError, ValueError):
        n = 1                       # unusable stored value (e.g. non-numeric) -> treat as fresh 0
    counts[host] = n
    try:
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(counts))
    except OSError:
        return 0
    return n


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
# Also unwraps two more shapes that previously blinded the lead/recon path entirely (the
# model early-returned before ever reaching inner_cmds()): a `-c`/`-e` code-exec payload
# (python3/node/bash/sh/perl/ruby/deno '<payload>') and a heredoc body. Both recurse so a
# wrapper NESTED inside one of these (e.g. vm.sh called from inside a `bash -c` body) still
# gets unwrapped too.
_CODE_C_RE = re.compile(
    r"^(?:\S*/)?(?:python3?|node|bash|sh|perl|ruby|deno)\s+-[ce]\s+(['\"])(.+)\1\s*$", re.S)
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)(\w+)\1\s*\n(.*?)\n\s*\2\b", re.S)
_LOOP_PREFIX = re.compile(r"^(?:do|then|;)\s+", re.I)


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
    # quote-aware split (Task 5): a raw ;/|/&&/||/newline split shreds a wrapper's quoted
    # arg when that arg itself contains one of these separators (e.g. vm.sh 'C=x; curl ...
    # | grep ...'), so the vm.sh/ssh/wsl regexes below never see the whole quoted arg and
    # this returns [] -- the missed-card bug. _segments() (Task 3) splits on the same
    # separator set but only OUTSIDE quoted spans, returning the original (un-blanked)
    # segment text -- a strict superset of the raw split for any command with no quoted
    # separator, so unquoted callers are unaffected.
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


def stage_shot(cmd, output, d):
    """Stage a recon/privesc tool's output for the loop-driver drain to render
    into a terminal-card PNG. Content-hash dedup; ordered by a .seq counter.
    Returns the staged path, or None (deduped / no output / error)."""
    import hashlib
    output = (output or "").strip()
    if not output:
        return None
    if _VMSCAN_RE.search(cmd):
        return None                     # vm-scan.sh launch: real output is in the tmux pane
    res = _shot_tool(cmd)               # (captured via --tmux), not this launcher echo -> don't card it
    if not res:
        return None
    tool, title = res
    pend = os.path.join(d, "recon", ".pending")   # scan images collect under recon/, not poc/
    try:
        os.makedirs(pend, exist_ok=True)
        h = hashlib.sha1(output.encode("utf-8", "ignore")).hexdigest()[:8]
        import glob
        if glob.glob(os.path.join(pend, "*-%s.txt" % h)):
            return None                     # already staged this exact output
        seqf = os.path.join(pend, ".seq")
        try:
            n = int(open(seqf, encoding="utf-8").read().strip() or "0")
        except Exception:
            n = 0
        n += 1
        with open(seqf, "w", encoding="utf-8") as fh:
            fh.write(str(n))
        path = os.path.join(pend, "%04d-%s-%s.txt" % (n, tool, h))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# " + title + "\n" + output)
        return path
    except Exception:
        return None


def _lead_request_context(cmd):
    """The 'request' context line for a lead card: the actual curl/wget invocation
    (wrapper-safe), or -- for a non-curl lead source -- a fingerprinted tool's command
    line, or a listener's command line, or (final fallback) ANY other recognized
    PROBE_TOOLS/CRED_TOOLS invocation (sqlmap, nxc, kerbrute, dig, ...). None only if
    truly nothing recognizable ran -- the genuinely un-auto-cardable case (a wholly
    custom/unknown command)."""
    inners = [cmd] + inner_cmds(cmd)
    for c in inners:                                  # the actual curl/wget invoked (wrapper-safe)
        if invokes(c, _REQ_TOOLS):
            m2 = re.search(r"((?:\S*/)?(?:curl|wget)\b[^\n;|&]*)", c, re.I)
            return (m2.group(1) if m2 else c.splitlines()[0]).strip()
    # non-curl lead source (a fingerprinted probe/recon/cred tool or a listener whose
    # OWN stdout carried the lead, e.g. nc -lvnp / http.server) -> fall back to that
    # tool's invoked command line as the "request" context.
    res = _shot_tool(cmd)
    if res:
        return res[1]
    for c in inners:
        if is_listener(c):
            return c.strip().splitlines()[0][:200]
    # final fallback: any other PROBE_TOOLS/CRED_TOOLS tool invoked at command position
    # (e.g. sqlmap, kerbrute) still gets carded instead of falling through to Area 3 --
    # a real win (a flag{...} in sqlmap output) should never go un-cardable just because
    # the tool isn't curl/wget/a screenshot-net scanner/a listener.
    for c in inners:
        m = invokes(c, PROBE_TOOLS) or invokes(c, CRED_TOOLS)
        if m:
            tool = m.group(1)
            m2 = re.search(r"((?:\S*/)?%s\b[^\n;|&]*)" % re.escape(tool), c, re.I)
            line = (m2.group(1) if m2 else c.splitlines()[0]).strip()
            return line[:200]
    return None


def stage_req_resp(cmd, output, d):
    """Stage a request+response (or tool-invocation+output) as a LEAD card for the Stop-hook
    drain to render into poc/leads/ (curated evidence, not the recon/ scan firehose). Caller
    fires this only when the response matched a lead signal. Content-hash dedup; .seq ordered.
    Returns the staged path or None. The card shows what ran (the curl command incl. its body,
    or -- for a non-curl lead source, e.g. a listener/probe tool whose OWN stdout carried the
    lead -- that tool's command line) and the output -- the moment a lead lands, captured
    without the model remembering."""
    import hashlib
    output = (output or "").strip()
    if not output:
        return None
    req = _lead_request_context(cmd)
    if not req:
        return None
    pend = os.path.join(d, "poc", "leads", ".pending")
    try:
        os.makedirs(pend, exist_ok=True)
        h = hashlib.sha1((req + output).encode("utf-8", "ignore")).hexdigest()[:8]
        import glob
        if glob.glob(os.path.join(pend, "*-%s.txt" % h)):
            return None                              # already staged this exact request+response
        seqf = os.path.join(pend, ".seq")
        try:
            n = int(open(seqf, encoding="utf-8").read().strip() or "0")
        except Exception:
            n = 0
        n += 1
        with open(seqf, "w", encoding="utf-8") as fh:
            fh.write(str(n))
        um = re.search(r"https?://\S+", req)
        title = ("curl " + um.group(0)) if um else req[:100]   # short title for the card bar
        body = "$ %s\n\n%s" % (req, output[:MAX_BLOB])          # full request + response in the body
        path = os.path.join(pend, "%04d-lead-%s.txt" % (n, h))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# " + title[:200] + "\n" + body)
        return path
    except Exception:
        return None


# --- website-story auto-capture (poc/pages/) --------------------------------
# Parallel net to the LEAD stager above: every in-scope HTML page (each auth-state)
# and every viewed source/config file gets a card in poc/pages/, so the engagement
# STORY is captured even when the model pipes/greps the response away instead of
# remembering to screenshot it. Scope gating lives in the CALLER (main()); this
# stager itself is scope-agnostic (mirrors stage_req_resp).
PAGE_CAP = 40   # ~cards/engagement before auto-capture goes quiet (one note, not a flood)
_HTML_CT_RE = re.compile(r"content-type\s*:\s*[^\r\n]*text/html", re.I)
_HTML_BODY_RE = re.compile(r"<html\b|<!doctype\s+html|<title\b", re.I)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_SRC_EXT_RE = re.compile(r"\.(?:php|js|json|log|conf|txt|env|ya?ml)(?:[?#]|$)", re.I)
_COOKIE_HDR_Q = re.compile(r"(?:-H|--header)\s+(['\"])\s*Cookie\s*:\s*(.*?)\1", re.I)
_COOKIE_FLAG_Q = re.compile(r"(?:-b|--cookie)\s+(['\"])(.*?)\1", re.I)
_COOKIE_FLAG_BARE = re.compile(r"(?:-b|--cookie)\s+([^\s'\"]+)", re.I)
_SCHEME_RE = re.compile(r"^\w+://", re.I)
_METHOD_VERB_RE = re.compile(r"(?:^|\s)(?:-X|--request)\s+(\S+)")
_WGET_METHOD_RE = re.compile(r"--method=(\S+)")
_GET_OVERRIDE_RE = re.compile(r"(?:^|\s)(?:-G|--get)(?=\s|$)")
_NONGET_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-d|--data|--data-raw|--data-binary|--data-ascii|--data-urlencode|"
    r"-F|--form|-T|--upload-file|--json|--post-data|--post-file)(?=[\s=]|$)")

# curl/wget value-taking flags: what the tool treats as a flag's VALUE vs a fetched URL.
# These decide which tokens are consumed (so they are NOT mistaken for request targets)
# and which remain positional targets. Case-sensitive (curl/wget short flags are). Note
# -O differs: curl -O is BOOLEAN (not here); wget -O TAKES a value (in WGET_SHORT_VALUE).
_CURL_LONG_VALUE = frozenset((
    "--cookie", "--cookie-jar", "--data", "--data-raw", "--data-binary", "--data-ascii",
    "--data-urlencode", "--form", "--form-string", "--header", "--config", "--max-time",
    "--connect-timeout", "--output", "--proxy", "--proxy-user", "--user", "--user-agent",
    "--referer", "--request", "--write-out", "--url", "--resolve", "--connect-to",
    "--cert", "--key", "--cacert", "--capath", "--range", "--interface", "--retry",
    "--retry-delay", "--limit-rate", "--oauth2-bearer", "--dns-servers", "--egd-file",
    "--hostpubmd5", "--continue-at", "--dump-header"))
_CURL_SHORT_VALUE = frozenset("bcdFHKmoxUuAeXwryYETCD")
_WGET_LONG_VALUE = frozenset((
    "--output-document", "--output-file", "--append-output", "--header", "--post-data",
    "--post-file", "--body-data", "--body-file", "--user-agent", "--referer",
    "--directory-prefix", "--user", "--password", "--load-cookies", "--save-cookies",
    "--execute", "--limit-rate", "--timeout", "--tries", "--bind-address",
    "--certificate", "--private-key", "--ca-certificate", "--quota", "--wait",
    "--waitretry", "--dns-timeout", "--connect-timeout", "--read-timeout",
    "--input-file", "--base"))
_WGET_SHORT_VALUE = frozenset("OoaUPeTtQiB")

# Opaque TARGET-SOURCE flags: they pull additional fetch targets from a source the argv
# parser cannot read (curl -K/--config config file with `url = ...` directives; wget
# -i/--input-file URL list). curl/wget fetch those IN ADDITION to the command-line URL and
# concatenate all bodies to stdout, so an out-of-scope target hidden in the file is
# invisible to argv enumeration. A segment carrying any of these is UNENUMERABLE -> the
# whole command fails closed (stage nothing). These are ALSO value-taking (in the *_VALUE
# sets above) so their file argument is consumed, not mistaken for a request target.
_CURL_OPAQUE_LONG, _CURL_OPAQUE_SHORT = frozenset(("--config",)), frozenset("K")
_WGET_OPAQUE_LONG, _WGET_OPAQUE_SHORT = frozenset(("--input-file",)), frozenset("i")
# Opaque BOOLEAN flags: take NO value, but content-drive a cross-host crawl -- wget
# -r/--recursive, -m/--mirror, -p/--page-requisites fetch from hosts DISCOVERED in fetched
# HTML, not present in argv. Argv-detectable (unlike a server-side redirect), so we fail
# closed on them too. Detection-only (no value consumed); curl has none.
_CURL_OPAQUE_BOOL_LONG, _CURL_OPAQUE_BOOL_SHORT = frozenset(), frozenset()
_WGET_OPAQUE_BOOL_LONG = frozenset(("--recursive", "--mirror", "--page-requisites"))
_WGET_OPAQUE_BOOL_SHORT = frozenset("rmp")

# Shell-redirect tokens: a naive shlex split of the whole command STRING does not know
# that the shell consumes a redirect operator (and its file/fd) before curl/wget ever see
# argv -- so `2>&1`, `2>/dev/null`, `> out.html`, `>>log`, `>&2` land in this token walk
# looking like an ordinary positional token. Safety invariant: a redirect operator and the
# file/fd it names are NEVER a URL curl/wget fetches (it is a local file the shell opens,
# or an fd dup) -- so skipping a redirect token can only fix a FALSE NEGATIVE (a redirect
# wrongly counted as a target); it can never make us under-count a REAL fetch target, and
# under-counting a real target is the only thing that can leak scope. So this is safe.
# BARE operator (its file is the NEXT token, e.g. `>`, `>>`, `<`, `2>`, `2>>`, `&>`, `&>>`).
_REDIR_BARE = re.compile(r"^(\d*(?:>>?|<)|&>>?)$")
# SELF-CONTAINED (an fd-dup or an attached filename in the SAME token, e.g. `2>&1`, `>&2`,
# `2>&-`, `2>/dev/null`, `>out.html`, `>>log`).
_REDIR_SELF = re.compile(r"^(\d*(?:>>?|<).+|&>>?.+|\d*>&\d*|\d*>&-)$")


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


def _target_host(token):
    """Host of a curl/wget request-target token, or None. Handles a scheme'd URL
    (http://h/..) AND a SCHEMELESS target (h/.. -- curl defaults to http://): take the
    authority up to the first /?#, then strip userinfo (user@) and :port, lowercase."""
    s = token or ""
    m = _SCHEME_RE.match(s)
    if m:
        s = s[m.end():]
    s = re.split(r"[/?#]", s, maxsplit=1)[0]
    s = s.split("@")[-1].split(":")[0].strip().lower()
    return s or None


def _curl_targets(segment):
    """(host, url) for every POSITIONAL request target of ONE curl/wget invocation segment,
    modeled on curl's own arg parsing: a request target is any positional token (a non-flag
    token that is not the value of a value-taking flag). This enumerates a SCHEMELESS host
    too (curl/wget default to http://), which a plain http(s):// regex under-counts -- the
    3rd leak shape. Safety invariant: under-counting a real target = a LEAK, over-counting
    = a harmless extra scope-check, so an UNKNOWN flag is treated as BOOLEAN (its following
    token stays a scope-checked target-candidate); only a KNOWN value-flag consumes its
    value. A shell-REDIRECT token (`2>&1`, `2>/dev/null`, `> out.html`, `>>log`) is also
    skipped -- not a flag and not a URL, so counting it as a target only produced a
    false-negative "out of scope" host (see _REDIR_BARE/_REDIR_SELF above); skipping it can
    never under-count a real target. Returns [] for a non-curl/wget segment.

    Returns the sentinel None (NOT a list) when the segment carries an OPAQUE target-source
    flag (curl -K/--config, wget -i/--input-file): those pull fetch targets from a file the
    argv parser cannot read, so targets are unenumerable and the caller must FAIL CLOSED
    (the 4th leak class). url = the target token with http:// prepended when schemeless."""
    import shlex
    try:
        toks = shlex.split(segment or "")
    except Exception:
        toks = (segment or "").split()
    # locate the curl/wget tool token (skip leading wrappers/env-assignments/their args)
    tool, i = None, 0
    while i < len(toks):
        base = toks[i].rsplit("/", 1)[-1].lower()
        if base in ("curl", "wget"):
            tool = base
            i += 1
            break
        i += 1
    if tool is None:
        return []
    if tool == "curl":
        long_val, short_val = _CURL_LONG_VALUE, _CURL_SHORT_VALUE
        opaque_long, opaque_short = _CURL_OPAQUE_LONG, _CURL_OPAQUE_SHORT
        opaque_bool_long, opaque_bool_short = _CURL_OPAQUE_BOOL_LONG, _CURL_OPAQUE_BOOL_SHORT
    else:
        long_val, short_val = _WGET_LONG_VALUE, _WGET_SHORT_VALUE
        opaque_long, opaque_short = _WGET_OPAQUE_LONG, _WGET_OPAQUE_SHORT
        opaque_bool_long, opaque_bool_short = _WGET_OPAQUE_BOOL_LONG, _WGET_OPAQUE_BOOL_SHORT
    targets, positional_only, opaque = [], False, False
    while i < len(toks):
        t = toks[i]
        if positional_only:                          # everything after a bare -- is a target
            targets.append(t); i += 1; continue
        if t == "--":
            positional_only = True; i += 1; continue
        if t.startswith("--"):
            if "=" in t:                             # --flag=val: consumes no separate token
                flag, _, val = t.partition("=")
                if flag in opaque_long or flag in opaque_bool_long:
                    opaque = True
                elif flag == "--url":
                    targets.append(val)
                i += 1; continue
            if t in opaque_long:                     # opaque long flag: consume its file value
                opaque = True; i += 2; continue
            if t in opaque_bool_long:                # boolean opaque (recursive/mirror): no value
                opaque = True; i += 1; continue
            if t in long_val:                        # known long value-flag: consume next token
                if t == "--url" and i + 1 < len(toks):
                    targets.append(toks[i + 1])
                i += 2; continue
            i += 1; continue                         # unknown/boolean long flag: consume nothing
        if t.startswith("-") and len(t) > 1:         # short flag cluster (maybe attached value)
            body = t[1:]
            if any(ch in opaque_short or ch in opaque_bool_short for ch in body):
                opaque = True                        # -K / -i / -r / -m / -p anywhere in cluster
            k = next((j for j, ch in enumerate(body) if ch in short_val), None)
            if k is None:                            # no value-flag char -> all boolean
                i += 1; continue
            if body[k + 1:]:                         # value attached in the same token
                i += 1; continue
            i += 2; continue                         # value is the NEXT token
        if _REDIR_BARE.match(t):                     # bare op: NEXT token is its redirect file/fd
            i += 2; continue
        if _REDIR_SELF.match(t):                     # self-contained: `2>&1`, `>out.html`, ...
            i += 1; continue
        targets.append(t); i += 1                    # bare token -> a positional request target
    if opaque:
        return None                                  # unenumerable targets -> caller fails closed
    out = []
    for tk in targets:
        h = _target_host(tk)
        if h:
            url = tk if _SCHEME_RE.match(tk) else "http://" + tk
            out.append((h, url))
    return out


def _all_targets(cmd):
    """(segment, host, url) for EVERY curl/wget request target across [cmd] + inner_cmds --
    segment-aware (via _segments) and wrapper-aware. This is the union the scope gate checks:
    a chained `curl in; curl out` (multiple segments), a multi-URL invocation, a --url list,
    and a SCHEMELESS out-of-scope arg are all surfaced, so the caller refuses the whole call
    when ANY target is out-of-scope (the concatenated stdout cannot be attributed per-URL).
    The first tuple is the representative (first in-scope target) for path/caption/cookie.

    Returns the sentinel None if ANY curl/wget segment is UNENUMERABLE (an opaque
    target-source flag: curl -K/--config, wget -i/--input-file) -- the whole command then
    fails closed (no card), because a target hidden in that file cannot be scope-checked."""
    out = []
    for c in [cmd] + inner_cmds(cmd):
        for seg in _segments(c):
            if invokes(seg, _REQ_TOOLS):
                tgs = _curl_targets(seg)
                if tgs is None:                      # opaque segment -> whole command unenumerable
                    return None
                for host, url in tgs:
                    out.append((seg, host, url))
    return out


def _url_path(url):
    """The URL path (query/fragment stripped) of url, or '/' if none."""
    m = re.match(r"https?://[^/\s]+(/[^?#\s]*)?", url, re.I)
    return (m.group(1) if m and m.group(1) else "/")


def _cookie_value(seg):
    """The session-cookie VALUE string (name=value) carried in a single curl/wget
    invocation segment (-b/--cookie, or an -H/--header 'Cookie: ...'), or None. Scans one
    segment (the representative in-scope invocation) so a chained call cannot attribute a
    different curl's cookie to this card."""
    for rx, grp in ((_COOKIE_HDR_Q, 2), (_COOKIE_FLAG_Q, 2), (_COOKIE_FLAG_BARE, 1)):
        m = rx.search(seg or "")
        if m:
            return m.group(grp).strip()
    return None


def _auth_state(seg):
    """Short sha1 of the invocation segment's session-cookie VALUE string, or the literal
    'anon' if no cookie -- so re-fetching the SAME path with a DIFFERENT cookie is a new
    auth-state (a second card), while the same path+cookie dedupes."""
    import hashlib
    cookie = _cookie_value(seg)
    if not cookie:
        return "anon"
    return hashlib.sha1(cookie.encode("utf-8", "ignore")).hexdigest()[:8]


def _http_method(seg):
    """"POST" for a non-GET curl/wget invocation segment -- a request-body/upload flag
    (-d/--data*, -F/--form, -T/--upload-file, --json, wget --post-data/--post-file) or an
    explicit non-GET verb (-X/--request, wget --method=) -- else "GET" (the default,
    including a None/empty seg). curl -G/--get always forces "GET" (curl folds -d onto
    the query string in that mode) regardless of any data flag present; an explicit
    -X GET / --method=GET is likewise "GET" even alongside a data flag. Guard/regex
    only scan of the segment string (mirrors _cookie_value/_auth_state) -- never raises."""
    try:
        s = seg if isinstance(seg, str) else ""
        if not s:
            return "GET"
        if _GET_OVERRIDE_RE.search(s):
            return "GET"
        m = _METHOD_VERB_RE.search(s) or _WGET_METHOD_RE.search(s)
        if m:
            verb = re.sub(r"[^A-Za-z]", "", m.group(1)).upper()
            return "GET" if (not verb or verb == "GET") else "POST"
        if _NONGET_FLAG_RE.search(s):
            return "POST"
        return "GET"
    except Exception:
        return "GET"


def _note_page_cap(pend):
    """Append ONE note line to the pending manifest once the poc/pages cap is hit
    (a .capped marker prevents re-appending on every subsequent capped call)."""
    marker = os.path.join(pend, ".capped")
    if os.path.isfile(marker):
        return
    try:
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write("1")
        with open(os.path.join(pend, "manifest.md"), "a", encoding="utf-8") as fh:
            fh.write("(cap reached: %d+ poc/pages cards staged, auto-capture paused)\n" % PAGE_CAP)
    except Exception:
        pass


def stage_page_or_source(cmd, output, d, url=None, req_seg=None):
    """Stage an in-scope HTML page (keyed by path+auth-state) or a leaked source/config
    file (keyed by URL) as a card in poc/pages/.pending/ for the loop-driver Stop drain --
    the website STORY captured even when the model pipes/greps the response away instead
    of screenshotting it. HTML takes precedence over the source-extension rule (a
    rendered .php that returns HTML is a PAGE, not a source). Content-hash-free dedup (a
    stable key, not the LEAD stager's content hash, so an auth-state's card is replaced
    in place by re-fetches rather than re-added); .seq ordered; capped at PAGE_CAP.
    Returns the staged path, or None (no output / not html-or-source / dedup / capped /
    error). Caller (main()) owns the scope + invocation gating and passes the vetted
    representative `url` + its `req_seg` (the single in-scope invocation segment); when
    omitted, self-resolves to the FIRST curl/wget invocation (used by the direct unit
    test only -- the main() path always vets scope first)."""
    import glob
    import hashlib
    output = (output or "").strip()
    if not output:
        return None
    if url is None:
        tgts = _all_targets(cmd)
        if not tgts:
            return None
        req_seg, _host, url = tgts[0]
    req_seg = req_seg or cmd
    blob = output[:MAX_BLOB]                      # truncate-before-scan (matches is_lead)
    path = _url_path(url)
    if _HTML_CT_RE.search(blob) or _HTML_BODY_RE.search(blob):
        kind = "page"
    elif _SRC_EXT_RE.search(path) or is_lead(output):
        kind = "source"
    elif _http_method(req_seg) == "POST":
        # A non-GET to an in-scope target (a login/upload/forged-body request) -- the
        # REQUEST is the evidence (the thm_tricipher request/response standard), even when
        # the response is a 302/JSON/empty and so matches neither the page nor lead rule.
        # This closes the "exploit POSTs were never auto-carded" gap. Deduped per
        # url+auth-state below, so re-firing the same POST replaces its card in place.
        kind = "request"
    else:
        return None
    pend = os.path.join(d, "poc", "pages", ".pending")
    try:
        os.makedirs(pend, exist_ok=True)
        existing = len(glob.glob(os.path.join(pend, "*.txt"))) + \
            len(glob.glob(os.path.join(d, "poc", "pages", "*.png")))
        if existing >= PAGE_CAP:
            _note_page_cap(pend)
            return None
        if kind == "page":
            key = hashlib.sha1((path + "|" + _auth_state(req_seg)).encode(
                "utf-8", "ignore")).hexdigest()[:8]
            m = _TITLE_RE.search(blob)
            title_txt = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
            caption = (url + " - " + title_txt) if title_txt else url
        elif kind == "request":
            # key on url+method+auth-state so a re-POST replaces its card, but a POST to a
            # different endpoint / at a different auth-state stages its own.
            key = hashlib.sha1(("POST|" + url + "|" + _auth_state(req_seg)).encode(
                "utf-8", "ignore")).hexdigest()[:8]
            caption = "POST " + url
        else:
            key = hashlib.sha1(url.encode("utf-8", "ignore")).hexdigest()[:8]
            caption = url
        if glob.glob(os.path.join(pend, "*-%s.txt" % key)):
            return None                              # already staged this path+auth-state / url
        seqf = os.path.join(pend, ".seq")
        try:
            n = int(open(seqf, encoding="utf-8").read().strip() or "0")
        except Exception:
            n = 0
        n += 1
        with open(seqf, "w", encoding="utf-8") as fh:
            fh.write(str(n))
        req_line = _lead_request_context(cmd) or ("curl " + url)
        body = "$ %s\n\n%s" % (req_line, output[:MAX_BLOB])
        browser = (kind == "page" and _http_method(req_seg) == "GET")
        if browser:
            meta_line = "#meta browser=1 url=%s\n" % re.sub(r"\s+", "", url or "")
        else:
            meta_line = "#meta browser=0\n"
        out_path = os.path.join(pend, "%04d-%s-%s.txt" % (n, kind, key))
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("# " + caption[:200] + "\n" + meta_line + body)
        return out_path
    except Exception:
        return None


def recent(path):
    try:
        return (time.time() - os.path.getmtime(path)) < STALE_SECONDS
    except OSError:
        return False


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


def _raw_stdout(data):
    """Raw terminal text for screenshotting: prefer the unwrapped stdout/stderr
    strings over the JSON-serialized tool_response (_response_text) so a staged
    terminal card renders real output, not a JSON blob."""
    r = data.get("tool_response")
    if isinstance(r, str):
        return r
    if isinstance(r, dict):
        joined = "\n".join(p for p in (r.get("stdout") or "", r.get("stderr") or "") if p)
        if joined:
            return joined
    return _response_text(data)


def active_research():
    """(name, dir) of the active research project from raw/research/active.md, or (None, None)."""
    try:
        import _engagement
        base = os.path.join(_engagement.VAULT, "raw", "research")
        p = os.path.join(base, "active.md")
        if not os.path.isfile(p):
            return (None, None)
        name = ""
        for line in open(p, encoding="utf-8", errors="ignore"):
            s = line.strip()
            if s and not s.startswith(("#", "<!--", "-")):
                name = s
                break
        d = os.path.join(base, name)
        return (name, d) if name and os.path.isdir(d) else (None, None)
    except Exception:
        return (None, None)


def fingerprint_hits(blob):
    """Return up to MAX_HITS ROUTING lines ('<tech> detected -> load Skill(x)') from
    playbook.json. Routing only: the named hunt skill owns the tests, tooling-first,
    payload arsenal, and cheatsheet reuse -- this hook surfaces the skill, it does not
    prescribe methodology."""
    try:
        import _engagement
        pb = os.path.join(_engagement.VAULT, "scripts", "playbook.json")
        fps = json.load(open(pb, encoding="utf-8"))["fingerprints"]
    except Exception:
        return []
    out = []
    nhits = 0
    for key, spec in fps.items():
        try:
            if not re.search(key, blob, re.IGNORECASE):
                continue
        except re.error:
            continue
        skills = spec.get("skills") or []
        label = key.split("|")[0].replace("\\b", "")   # clean regex tokens for display
        sk = (" -> load " + ", ".join("Skill(%s)" % s for s in skills)) if skills else ""
        out.append(f"  {label} detected{sk}")
        nhits += 1
        if nhits >= MAX_HITS:
            break
    return out


# Framework-meta guard: a command that reads/edits the vault's OWN wiring/hook/playbook
# machinery is NOT target recon. Its output is full of playbook tokens (hunt-<class> skill
# names, fingerprint regexes, payload/technique page names) that would otherwise false-match
# the fingerprint router and get surfaced as a "discovered surface" (observed live: editing
# playbook.json / running apply-wiring falsely fingerprinted as deserialization/sqli). These
# tokens never appear in genuine target recon, so a plain presence check on the command is safe.
_FRAMEWORK_META = re.compile(
    r"playbook\.json|triggers\.json|wiki-wiring|apply-wiring|_wiring-exempt|"
    r"recon-capture|loop-driver|hunt-trigger|scope-guard|engagement-init|"
    r"scripts/(?:playbook|wiki|gen_index|build_moc|wl-add|wiki-stage|check-hooks)|"
    r"skills/hooks|/vault-hooks/", re.IGNORECASE)


def _is_framework_meta(cmd):
    """True if the command operates on the vault's own framework machinery (playbook/hooks/
    wiki-wiring), so the fingerprint router must NOT treat its output as target recon."""
    return bool(_FRAMEWORK_META.search(cmd or ""))


# --- SSRF sink auto-router -------------------------------------------------
# Fire only when a fetch-param value is itself URL-ish / internal, or a raw SSRF
# protocol is in use, or the output shows an SSRF tell. Specific enough to run
# inside heredoc/-c bodies (SSRF testing is often wrapped, e.g. an SSH-to-VM
# driver) without firing on benign curls (a plain CDN fetch has no sink param).
_SSRF_SINK = re.compile(
    r"[?&](?:url|uri|src|source|dest|destination|redirect|redir|return|next|"
    r"callback|image|imageurl|img|fetch|load|link|feed|host|target|proxy|"
    r"preview|unfurl|screenshot|import|webhook|site|page|u|q)="
    r"[^&\s'\"]*?(?:https?:|https?%3a|gopher:|dict:|file:|ftp:|ldap:|sftp:|"
    r"127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|metadata\.google|\[?::1\]?)",
    re.I)
_SSRF_PROTO = re.compile(r"\b(?:gopher|dict|sftp|ldap)://", re.I)
# specific runtime tells only (NOT the bare word "SSRF" - that fires on any doc/notes output)
_SSRF_TELL = re.compile(r"URL blocked due to keyword|blocked due to.*(?:scheme|protocol|host|ip)|"
                        r"169\.254\.169\.254|iam/security-credentials|computeMetadata/v1",
                        re.I)
# the model is already sweeping internal ports -> don't nag
_SSRF_SWEEPING = re.compile(r"for\s+\w+\s+in\s+\$?\(?\s*seq\s|127\.0\.0\.1:\$|in\s+\{[\d,]*\d{3,}", re.I)
# pull host/path/param of the OUTER sink request to template the sweep
_OUTER_SINK = re.compile(r"https?://([^/\s'\"]+)(/[^?\s'\"]*)\?(\w+)=", re.I)
_HOSTLIT = re.compile(r"^[A-Za-z0-9.\-]+$")   # literal host (no shell var) -> safe to inline
# a real fetch must be present (so a sink URL merely pasted in notes/heredoc data won't fire)
_FETCH = re.compile(r"\bcurl\b|\bwget\b|requests\.(?:get|post)|urlopen|file_get_contents|fopen|"
                    r"Invoke-WebRequest|http[._]?get|\bnc\b|fetch\(|hackvertor", re.I)


def ssrf_sink_guidance(cmd, out, d, eng):
    """If a command reveals an SSRF sink, surface a pre-templated internal port
    sweep + the gopher primitive, RoE-gated. ADVISORY (does not execute). Dedups
    per sink via a marker in the engagement dir so it nudges once, not every probe."""
    # Match SINK+FETCH and PROTO against the COMMAND only. A sink URL merely present
    # in a command's OUTPUT (git show / cat / head of notes or ssrf.md, grep of a log)
    # must not fire the router -- that is cry-wolf on a hook meant to be specific.
    # Output-driven detection stays limited to the specific _SSRF_TELL runtime markers.
    c = cmd[:MAX_BLOB]
    if _SSRF_SWEEPING.search(c):
        return []
    if not ((_SSRF_SINK.search(c) and _FETCH.search(c))
            or _SSRF_PROTO.search(c) or _SSRF_TELL.search(out or "")):
        return []
    m = _OUTER_SINK.search(cmd)
    path, param = (m.group(2), m.group(3)) if m else ("/<sink-path>", "url")
    host = m.group(1) if m else ""
    tline = "T=%s; " % host if (host and _HOSTLIT.match(host)) else "T=<target>; "
    sc, etype = {}, None
    try:
        if d and eng:
            sc = eng.scope(d) or {}
            etype = eng.engagement_type(d)
    except Exception:
        sc = {}
    # dedup per sink (host|path|param)
    key = "%s|%s|%s" % (host or "?", path, param)
    if d:
        try:
            seen_p = os.path.join(d, ".ssrf-seen")
            seen = open(seen_p, encoding="utf-8").read().splitlines() if os.path.isfile(seen_p) else []
            if key in seen:
                return []
            with open(seen_p, "a", encoding="utf-8") as fh:
                fh.write(key + "\n")
        except Exception:
            pass
    if sc.get("passive_only"):
        return ["SSRF sink detected (%s?%s=). RoE=passive_only -> do NOT port-sweep; confirm via OOB "
                "only and log the oob.md row. Load Skill(hunt-ssrf)." % (path, param)]
    sweep = (tline + 'for P in $(seq 1 65535); do R=$(curl -s -m3 '
             '"http://$T%s?%s=http://127.0.0.1:$P/"); '
             '[ -n "$R" ] && echo "OPEN $P len=${#R}"; done') % (path, param)
    dos = " RoE=no_dos: throttle - scan a top-ports list slowly, not the full range fast." if sc.get("no_dos") else ""
    return [
        "SSRF sink detected.%s INTERNAL-FIRST: an internal-only service is usually the objective and "
        "is invisible to external nmap. Sweep 127.0.0.1 THROUGH the sink, then fingerprint each open "
        "port + route it through playbook.json BY HAND (recon-capture does NOT fingerprint "
        "SSRF-discovered services):\n  %s\n"
        "Need a header/method/cookie (Next.js CVE-2025-29927 x-middleware-subrequest, HTTP Basic auth, "
        "POST login, forged cookie)? A ?url= GET can't set those -> use the gopher raw-request builder "
        "in wiki/payloads/ssrf.md. Load Skill(hunt-ssrf)." % (dos, sweep)
    ]


# --- GUI + live-tmux capture nudges ----------------------------------------
# The auto screenshot path (stage_shot -> loop-driver drain) renders `shot.py --term`
# only: it cards the STDOUT text a foreground command returned. Two evidence surfaces
# it can never reach on its own -- a GUI window (Burp/Wireshark: no console stream) and
# a scan running DETACHED in a tmux pane (its output never comes back through this Bash
# response). shot.py has --window/--screen (scrot/import) and --tmux for exactly these,
# but nothing invokes them. These nudges fire the moment such a surface appears so the
# capability is actually used, without the hook itself executing a tool.
_GUI_APPS = {"burpsuite": "Burp Suite", "burp": "Burp Suite", "wireshark": "Wireshark",
             "zaproxy": "OWASP ZAP", "ghidra": "Ghidra"}
# command-position (path/wrapper tolerant, like _shot_tool) so `ls /opt/burpsuite` is inert
_GUI_RE = re.compile(r"(?<![\w/.])(burpsuite|burp|wireshark|zaproxy|ghidra)\b", re.I)
# a REAL vm-scan.sh launch: invoked via bash/sh at command position, with a session + target +
# a scan arg. Tightened so `bash -n scripts/vm-scan.sh` (syntax check), `cat`/`grep vm-scan.sh`,
# or a bare mention does NOT fire (session/target exclude shell metachars, so `&& echo` can't match).
_VMSCAN_RE = re.compile(
    r"(?:^|[;&|\n]+)\s*(?:bash|sh)\s+\S*vm-scan\.sh\s+(?:--dry-run\s+)?"
    r"([^\s;&|]+)\s+([^\s;&|]+)\s+\S", re.I)


def gui_capture_guidance(cmd):
    """Nudge a scrot/import window grab when a GUI app is launched (the --term stdout
    path can't card a GUI). [] if no GUI app in the command."""
    m = _GUI_RE.search(cmd or "")
    if not m:
        return []
    app = m.group(1).lower()
    title = _GUI_APPS.get(app, app)
    return [
        "GUI app launched (%s). The auto screenshot path only cards CLI stdout -- a GUI window needs a "
        "scrot/import grab. At a state worth showing (intercepted request, a scanner finding, the rendered "
        "exploit) capture it:\n"
        "  bash /root/vm.sh 'python3 /tmp/shot.py --window \"%s\" -o /tmp/poc/%s.png'\n"
        "then pull the PNG into targets/<eng>/poc/ (deliberate PoC arc). --window falls back to full screen "
        "if the title is not found; --screen grabs the whole desktop. Load Skill(screenshot) for the flow."
        % (app, title, app)
    ]


def tmux_capture_guidance(cmd):
    """Nudge the live-pane grab when a scan is launched DETACHED via vm-scan.sh -- its
    output never returns through this Bash response, so --term can't card it. [] otherwise."""
    m = _VMSCAN_RE.search(cmd or "")
    if not m:
        return []
    session, target = m.group(1), m.group(2)
    name = re.sub(r"[./: ]", "-", target)               # same sanitize as vm-scan.sh (tr './: ' '----')
    return [
        "Scan launched DETACHED in tmux tab %s:%s -- its output will NOT come back through this command, so "
        "the auto --term path can't card it. Once the pane has output, grab the LIVE pane:\n"
        "  bash /root/vm.sh 'python3 /tmp/shot.py --tmux %s:%s -o /tmp/poc/%s.png'\n"
        "then pull the PNG into targets/<eng>/poc/. Target the tab by the @NN id or the sanitized name "
        "vm-scan.sh printed. Load Skill(screenshot) for the flow." % (session, name, session, name, name)
    ]


def wiki_stage_nudge(is_cred, lead_hit):
    """Advisory nudge to distill GENERIC reusable knowledge into the wiki-candidate inbox
    when a default/known cred was captured or a reusable-request lead landed. [] otherwise.
    Advisory only: never executes, never blocks."""
    if is_cred:
        return ["Reusable knowledge? If a DEFAULT/known product credential, stage a GENERIC "
                "wiki candidate now (no client host): "
                "python3 scripts/wiki-stage.py --kind default-cred --slug <product>-default "
                "-> review/promote via scripts/wiki-promote.py."]
    if lead_hit:
        return ["Reusable knowledge? If this request pattern generalizes (product + endpoint + "
                "impact), stage a GENERIC wiki candidate: "
                "python3 scripts/wiki-stage.py --kind api-pattern --slug <product>-<endpoint> "
                "-> promote later via scripts/wiki-promote.py."]
    return []


# --- ctf discipline nudge (fire-once) ---------------------------------------
# On thm_sequence the model bypassed the methodology: a raw one-shot `bash /root/vm.sh
# '<exploit>'` + inline `node -e` JS, no tmux-per-action, ctf-box never loaded. This nudge
# steers back to the disciplined tmux path (scripts/vm-scan.sh) the moment an off-script
# exploitation shape (a listener/reverse-shell, or inline code-exec through a bridge
# wrapper) runs foreground in an active CTF engagement. Advisory only, fire-once.
_BRIDGE_RE = re.compile(
    r"(?:^|[;&|\n]\s*)(?:bash\s+)?\S*vm\.sh\b"          # bash /root/vm.sh '...'
    r"|(?:sshpass\b.*?\s)?\bssh\b[^\n]*\s\S+@\S+"       # ssh [opts] user@host '...'
    r"|\bwsl\b[^\n]*--",                                # wsl [...] -- ...
    re.I)
_CODE_EXEC_RE = re.compile(r"\b(?:node|python3?|bash|sh|perl|ruby)\s+-[ce]\b", re.I)
_DETACHED_RE = re.compile(r"\bnohup\b|\btmux\b|&\s*$", re.I)


def discipline_nudge(cmd, inners, d, _engagement):
    """Fire-once advisory nudge: in an active CTF engagement, an off-script exploitation
    shape (a raw listener/reverse-shell, or inline code-exec run through a bridge wrapper
    like vm.sh/ssh/wsl) that skips the disciplined tmux path (scripts/vm-scan.sh). []
    otherwise. Advisory only, never blocks. Fails open: any error -> no nudge."""
    if not d or not _engagement:
        return []
    try:
        etype = _engagement.engagement_type(d)
    except Exception:
        return []
    if etype != "ctf":
        return []
    try:
        cmd = cmd or ""
        if _VMSCAN_RE.search(cmd) or _DETACHED_RE.search(cmd):
            return []          # already disciplined (vm-scan.sh) or detached (nohup/tmux/&)
        # Match command STRUCTURE, not tokens quoted in a commit message or a heredoc note.
        # Strip heredoc bodies, then blank quoted spans (as invokes() does), so a
        # `git commit -m "...nc -l...vm.sh node -e..."` or a `cat <<EOF ...nc -l... EOF`
        # note is NOT read as an invocation. Inner-command tokens (the real exploit inside a
        # vm.sh/ssh quoted arg) are inspected ONLY when a bridge wrapper is genuinely invoked
        # (the bridge gate) -- a heredoc body fed to cat/tee is never a bridge.
        top = _blank_quotes(_HEREDOC_RE.sub(" ", cmd))
        bridge = bool(_BRIDGE_RE.search(top))
        listener = bool(_LISTENER_RE.search(top)) or (
            bridge and any(is_listener(ic) for ic in (inners or [])))
        code_exec = bool(_CODE_EXEC_RE.search(top)) or (
            bridge and any(_CODE_EXEC_RE.search(ic or "") for ic in (inners or [])))
        off_script = listener or (bridge and code_exec)
        if not off_script:
            return []
        marker = os.path.join(d, ".discipline-nudged")
        if os.path.isfile(marker):
            return []          # one reminder per box
        try:
            with open(marker, "w", encoding="utf-8") as fh:
                fh.write(time.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception:
            pass
        return [
            "DISCIPLINE (ctf): running exploitation via a raw one-shot vm.sh dodges the "
            "methodology. Run persistent/interactive steps (listeners, shells, chained "
            "exploits) in their own named tmux tab -- scripts/vm-scan.sh <eng> <target> "
            "'<cmd>' -- so the session is captured as evidence and survives a dropped "
            "vm.sh call, and go wiki-first before hand-rolling. Load Skill(ctf-box)."
        ]
    except Exception:
        return []


def _areas_to_kick(d, debounce=8):
    """Areas whose .pending has a staged [0-9]*.txt card AND was not kicked in the last
    `debounce` seconds. Writes a `.last-kick` stamp for each area it returns (so the caller
    spawns at most one drain per area per debounce window). Returns a list like
    ['recon', 'poc/pages']. Never raises."""
    out = []
    for area in ("recon", "poc/leads", "poc/pages"):
        try:
            pend = os.path.join(d, *area.split("/"), ".pending")
            if not (os.path.isdir(pend) and any(
                    f.endswith(".txt") and f[:1].isdigit() for f in os.listdir(pend))):
                continue
            stamp = os.path.join(pend, ".last-kick")
            if os.path.isfile(stamp) and (time.time() - os.path.getmtime(stamp)) < debounce:
                continue
            try: open(stamp, "w").close()
            except OSError: pass
            out.append(area)
        except Exception:
            continue
    return out


def _kick_drains(d, debounce=8):
    """Spawn the detached loop-driver --drain for each staged+undebounced area (and
    --drain-tmux if .pending-tmux is non-empty), so cards render mid-turn. Best-effort,
    detached, never blocks. Never raises."""
    import subprocess
    ld = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loop-driver.py")
    if not os.path.isfile(ld):
        return
    for area in _areas_to_kick(d, debounce):
        try:
            subprocess.Popen([sys.executable, ld, "--drain", d, area],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
        except Exception:
            pass
    try:
        tm = os.path.join(d, ".pending-tmux")
        if os.path.isfile(tm) and os.path.getsize(tm) > 0:
            stamp = os.path.join(d, ".last-kick-tmux")
            if not (os.path.isfile(stamp) and (time.time() - os.path.getmtime(stamp)) < debounce):
                try: open(stamp, "w").close()
                except OSError: pass
                subprocess.Popen([sys.executable, ld, "--drain-tmux", d],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass


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

    # active engagement dir (computed once; used by SSRF RoE gating, OOB correlation, capture marker)
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        _engagement = None
        d = None

    out = _response_text(data)

    # SSRF-sink auto-router: runs EVEN for heredoc/-c bodies (the sink signature is
    # specific), because SSRF testing is often wrapped (e.g. an SSH-to-VM driver).
    # Pure echo/printf/cat/comment = discussion, not a real fetch -> suppress.
    ssrf_blocks = []
    if not re.match(r"\s*(#|echo\b|printf\b|cat\b)", cmd, re.IGNORECASE):
        ssrf_blocks = ssrf_sink_guidance(cmd, out, d, _engagement)

    # Capture nudges for the two surfaces the --term auto path can't reach: a GUI window
    # (Burp/Wireshark) and a scan running detached in a tmux pane. Engagement-gated (they
    # point at the poc/ evidence dir). Surfaced on every command shape, including wrapped.
    cap_blocks = []
    if d:
        cap_blocks = gui_capture_guidance(cmd) + tmux_capture_guidance(cmd)

    # Skip the REST (fingerprint/capture) for commands that only mention a tool name in
    # pure documentation/discussion (a comment, an echo, a cat/grep/rg of some file) --
    # but still surface any SSRF/capture guidance found above. Code-exec shapes (node -e /
    # python3 -c / bash -c / sh -c / a heredoc body) used to ALSO return here, blinding the
    # lead/recon path entirely -- that carried real exploitation work (e.g. thm_sequence's
    # XSS/browser chain). inner_cmds() now recurses into -c/-e and heredoc payloads, so
    # those shapes fall through into the same tool-test + lead-capture pipeline below
    # instead of being suppressed.
    if re.match(r"\s*(#|echo\b|printf\b|cat\b|grep\b|rg\b)", cmd, re.IGNORECASE):
        _emit(ssrf_blocks + cap_blocks)
        return

    # command-position match: the tool must be invoked, not just named in a path/arg.
    # Also check inside vm.sh/ssh/wsl bridge wrappers, where the real tool sits inside
    # a quoted inner command that invokes() alone (outer cmd only) would miss.
    _inners = inner_cmds(cmd)

    def _inv(tools):
        return invokes(cmd, tools) or next((m for ic in _inners if (m := invokes(ic, tools))), None)
    is_recon = _inv(RECON_TOOLS)
    is_cred = _inv(CRED_TOOLS)
    is_probe = _inv(PROBE_TOOLS)
    is_listener_hit = is_listener(cmd) or any(is_listener(ic) for ic in _inners)
    # a lead is worth staging when it lands on the stdout of ANY probe/exec tool we already
    # recognize (curl/wget request, a fingerprinted recon/probe/cred tool, or a listener
    # catching an out-of-band callback) -- not curl/wget alone (the old net's blind spot).
    lead_signal = is_lead(_raw_stdout(data)) and bool(
        _inv(_REQ_TOOLS) or is_probe or is_recon or is_cred or is_listener_hit)

    blocks = list(ssrf_blocks) + list(cap_blocks)

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
    #    Skip framework-meta commands: editing/reading the vault's own playbook/wiki/hooks
    #    emits playbook tokens that would false-fingerprint as a discovered surface.
    if is_probe and not _is_framework_meta(cmd):
        blob = (cmd + "\n" + _response_text(data))[:MAX_BLOB]
        hits = fingerprint_hits(blob)
        if hits:
            blocks.append(
                "Tech fingerprinted (playbook.json) -> load the hunt Skill named below; it "
                "carries the wiki-first, tooling-first, tests, and payload steps:\n"
                + "\n".join(hits)
            )

    # 2. research-loop nudge (a CVE-research tool ran + a research project is active)
    rt = re.search(RESEARCH_TOOLS, cmd, re.IGNORECASE)
    if rt:
        rname, _ = active_research()
        if rname:
            blocks.append(
                f"Research tool ({rt.group(0)}) + active project {rname}. Capture: a crash/leak/finding -> "
                f"raw/research/{rname}/findings.md; log the iteration in loop.md (approach -> result -> next); "
                f"then run scripts/research_status.py -q for the next move."
            )

    # 3. capture nudge (engagement-gated): advisory reminder to persist recon/creds
    if (is_recon or is_cred) and d and _engagement:
        targets = []
        if is_recon and not recent(os.path.join(d, "state.md")):
            targets.append("state.md (hosts/services/access)")
        if is_cred and not recent(os.path.join(d, "loot.md")):
            targets.append("loot.md (credentials + reuse map)")
        if targets:
            tool = (is_cred or is_recon).group(1)
            eng = os.path.basename(os.path.normpath(d)) or "<engagement>"
            tp = _tool_page(tool)   # surface the tool's wiki page (cred tools too, not just probe)
            blocks.append(
                f"Recon/exec tool detected ({tool}). Capture results: drop raw output in "
                f"targets/{eng}/ingest/ and run the ingest skill, or extract directly into "
                + " and ".join(targets)
                + ". Update paths.md if this opened or blocked an attack path."
                + (f"\n  tool ref: {tp}" if tp else "")
            )

    # stage recon/privesc tool output for a terminal-card screenshot (drained at Stop).
    # Engagement-gated only; _shot_tool self-gates (path/wrapper tolerant) so privesc
    # scripts (linpeas/pspy) and vm-wrapped scanners stage too.
    if d and _engagement:
        try:
            stage_shot(cmd, _raw_stdout(data), d)
        except Exception:
            pass

    # lead auto-capture: ANY probe/exec tool (curl/wget request, a fingerprinted recon/probe/
    # cred tool, or a listener) whose stdout shows a lead signal (cred/flag/secret/leaked
    # source) -> stage a card (poc/leads/, drained at Stop), so a lead is captured the MOMENT
    # it lands, without the model remembering. reqshot gives the full-headers version; this
    # net catches leads even from a plain curl, a scan tool's own output, or a listener's
    # stdout (nc -l / http.server) -- the thm_sequence blind spot (an XSS beacon calling back
    # to a listener never transits a curl response).
    if d and _engagement and lead_signal:
        try:
            raw_out = _raw_stdout(data)
            if stage_req_resp(cmd, raw_out, d):
                eng = os.path.basename(os.path.normpath(d)) or "<engagement>"
                # Live synchronous render: leads are rare + high-value, so a bounded
                # render right now (chromium via loop-driver.py --drain) beats deferring
                # to the Stop-hook drain, which is SKIPPED whenever the turn is an
                # auto-continue chain (stop_hook_active) -- exactly when a staged lead
                # would otherwise sit un-rendered for the rest of the chain. The .txt was
                # already staged above, so a timeout/error here just leaves it for the
                # (now-fixed) Stop-drain -- fail-open, never blocks/crashes this hook.
                try:
                    import subprocess
                    subprocess.run(
                        [sys.executable, os.path.join(HERE, "loop-driver.py"),
                         "--drain", d, "poc/leads"],
                        capture_output=True, timeout=RENDER_TIMEOUT)
                except Exception:
                    pass
                nudge = ("LEAD auto-captured to poc/leads/ (a credential/flag/secret/leaked "
                         "source landed); rendering now (falls back to the next Stop if slow).")
                if _inv(_REQ_TOOLS) and not re.search(r"\bcurl\b[^\n;|&]*-\w*[iv]", cmd):
                    nudge += (" This curl had no -i/-v so response headers are missing -- for a full "
                              "request+response PoC re-run it via "
                              "`scripts/reqshot.sh %s <slug> -- <curl-args>`." % eng)
                blocks.append(nudge)
        except Exception:
            pass

    # website-story auto-capture: an in-scope curl/wget response that is an HTML page
    # (each distinct auth-state) or a raw leaked source/config file -> stage a card to
    # poc/pages/ (drained at Stop), so the engagement STORY is captured even when the
    # model pipes/greps the response away. Silent (no nudge text): a parallel capture
    # net, not an advisory.
    #
    # Per-TARGET scope gate (not per-blob, not per-first-URL): _all_targets() enumerates
    # EVERY request target curl/wget will actually fetch, modeled on curl's arg parsing --
    # so a chained `curl in; curl out`, a multi-URL invocation, a --url list, AND a
    # SCHEMELESS out-of-scope arg (curl defaults to http://) are all surfaced. Staging is
    # refused wholesale unless EVERY target host is in-scope (empty union -> fail closed),
    # because the concatenated stdout cannot be attributed per-URL and would otherwise write
    # an out-of-scope host's response to disk under the in-scope label. The first target is
    # the representative for path/caption/cookie extraction. _all_targets() returns the None
    # sentinel when a segment carries an opaque target-source flag (curl -K/--config, wget
    # -i/--input-file) whose file could add unenumerable out-of-scope targets -> falsy here
    # -> fail closed (no card).
    if d and _engagement and _inv(_REQ_TOOLS):
        try:
            sc = _engagement.scope(d)
            tgts = _all_targets(cmd)
            if tgts and all(h and _in_scope(h, sc) for _seg, h, _u in tgts):
                seg0, _h0, url0 = tgts[0]
                stage_page_or_source(cmd, _raw_stdout(data), d, url=url0, req_seg=seg0)
        except Exception:
            pass

    # wiki-candidate stage nudge: a captured default/known cred or a reusable-request lead
    # is generic knowledge worth distilling. Advisory, fail-open.
    if d and _engagement:
        try:
            blocks += wiki_stage_nudge(bool(is_cred), lead_signal)
        except Exception:
            pass

    # per-host hand-curl repetition nudge: only an in-scope host, only a real curl/wget
    # invocation (wrapper-aware via _inv), suppressed under tunnel_safe. Fires once, when a
    # host's count first reaches CURL_REPEAT_THRESHOLD. Advisory-only, fails open.
    if d and _engagement and _inv(_REQ_TOOLS):
        try:
            sc = _engagement.scope(d)
        except Exception:
            sc = {}
        host = _probe_host(cmd)
        if host and not sc.get("tunnel_safe") and _in_scope(host, sc):
            n = _bump_curl_count(d, host)
            if n == CURL_REPEAT_THRESHOLD:
                blocks.append(
                    "TOOLING-FIRST: you have hand-curled %s %d times this session -> switch to "
                    "`httpx` (probe/title/tech), `ffuf` (content discovery), or `nuclei` (templated "
                    "checks) for the rest. A one-off curl is fine; repeating it reimplements the tool."
                    % (host, n))

    # ctf discipline nudge: off-script exploitation (raw listener, or inline code-exec via
    # a bridge wrapper) in a CTF engagement, outside the disciplined vm-scan.sh tmux path --
    # steer back to the methodology. Fire-once (.discipline-nudged marker). Fails open.
    if d and _engagement:
        try:
            blocks += discipline_nudge(cmd, _inners, d, _engagement)
        except Exception:
            pass

    # screenshot-on-finding reflex (capture, not methodology): the FIRST time a finding lands
    # this engagement -- a flag read, or a shell/privesc `id` output -- prompt Skill(screenshot)
    # of the DELIBERATE exploited/authed state now. The lead auto-card captures a request; it does
    # NOT capture the visual proof (a post-login dashboard, a payload firing, a live shell), and a
    # transient state cannot be re-shot after the turn. Fire-once per engagement so the discipline
    # is planted at the first success without spamming every later `id`.
    if d and _engagement:
        try:
            raw = _raw_stdout(data)
            mk = os.path.join(d, ".screenshot-nudged")
            if raw and _FINDING_RE.search(raw[:MAX_BLOB]) and not os.path.exists(mk):
                open(mk, "w").close()
                blocks.append(
                    "FINDING landed -> Skill(screenshot) the live exploited/authed STATE now "
                    "(post-login dashboard, the payload firing, or the shell via --tmux) so it can "
                    "be manually reviewed. Do this at EACH success as it lands, not at the end: the "
                    "auto lead/page cards catch requests, not the deliberate visual proof, and a "
                    "transient state cannot be re-captured after this turn.")
        except Exception:
            pass

    # recon-completeness reflex (coverage, not methodology): record content-discovery tools when
    # they run; the FIRST time an in-scope web probe happens with NONE recorded, surface the gap
    # once. thm_biblioteca gap: reached foothold with ffuf never run -- a hidden route is often the
    # intended path. This is a factual "did discovery run?", not a "how to test" prescription.
    if d and _engagement:
        try:
            rec = os.path.join(d, ".recon-tools")
            disc = _inv(_DISCOVERY_TOOLS)
            if disc:
                with open(rec, "a", encoding="utf-8") as fh:
                    fh.write(disc.group(0).lower() + "\n")
            elif _inv(_REQ_TOOLS) or _inv(r"whatweb"):
                try:
                    sc = _engagement.scope(d)
                except Exception:
                    sc = {}
                host = _probe_host(cmd)
                ran = os.path.exists(rec) and open(rec, encoding="utf-8", errors="ignore").read().strip()
                gap = os.path.join(d, ".recon-gap-nudged")
                if host and _in_scope(host, sc) and not ran and not os.path.exists(gap):
                    open(gap, "w").close()
                    blocks.append(
                        "RECON COMPLETENESS: web-probing an in-scope host but no automated discovery "
                        "has run this engagement. A hidden route/param is often the intended path -- "
                        "run ffuf/feroxbuster (content), arjun (parameters), and nuclei (CVE/misconfig) "
                        "BEFORE manual browsing or registering an account. Silences once content "
                        "discovery runs.")
        except Exception:
            pass

    # drainkick: also kick the SAME idempotent, detached loop-driver drain here (not just
    # at Stop), so staged evidence cards render mid-turn as they land instead of clustering
    # at turn-end. Best-effort, detached, never blocks this hook.
    if d:
        try:
            _kick_drains(d)
        except Exception:
            pass
    _emit(blocks)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
