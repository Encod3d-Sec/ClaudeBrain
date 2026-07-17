#!/usr/bin/env python3
"""PreToolUse(Bash) hook: ENFORCING scope + RoE + output-hygiene guard.

Before a shell command runs, DENY it (permissionDecision: deny -> the tool call is
blocked, the reason is shown) when it deterministically:
  - emits an `echo "=== ... ==="` output-banner (CLAUDE.md forbids it; fires
    regardless of engagement), or
  - targets an out-of-scope host/IP (exact host/domain match or IP-in-CIDR against
    scope.md's out_of_scope list), or
  - uses tooling forbidden by the engagement RoE flags
    (no_bruteforce / no_dos / passive_only in scope.md).

This is the harness's "enforce, don't nudge" boundary: these three are DETERMINISTIC
(no judgement), so blocking them costs no tokens/time and prevents the wrong action
outright. Semantic workflow steps (wiki-first, tools-not-manual, capture, intended-path)
stay advisory elsewhere -- hard-blocking a judgement call would false-fire and make us
MORE stuck, the opposite of the goal.

SAFETY (this hook can block, so it must never trap the operator):
  - Fail-OPEN: any exception -> exit 0, allow. A hook bug never blocks a command.
  - Narrow matches only: out-of-scope needs an explicit out_of_scope entry (empty on a
    typical single-target CTF -> never fires); RoE denies need the flag set.
  - Escape hatch: create `skills/hooks/.enforce-off` (== the hooks dir) to instantly
    downgrade every deny back to an advisory warning, for when a false-block gets in the way.
No active engagement -> only the output-banner check runs. Any error exits 0 silent.
"""
import ipaddress
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
# file extensions that HOST_RE would otherwise match as "hosts" (config.yml, app.py...)
FILE_EXT = {"json", "yml", "yaml", "md", "sh", "py", "txt", "js", "ts", "go", "rs",
            "conf", "cfg", "ini", "toml", "lock", "log", "csv", "xml", "html", "css",
            "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "tar", "gz", "bak", "tmp",
            "c", "cpp", "h", "java", "rb", "php", "env", "example", "local", "sample"}

BRUTEFORCE = re.compile(r"\b(hydra|medusa|patator|ncrack|kerbrute)\b|--password-file|\bspray(ing|hound)?\b|-P\s+\S+\.txt", re.I)
DOS = re.compile(r"\b(slowloris|hping3|stress-ng|siege|t50)\b|--flood|--min-rate\s+[0-9]{5,}|nmap[^|;&]*-T5|\bab\b[^|;&]*-n\s+[0-9]{5,}", re.I)
ACTIVE = re.compile(r"\b(nmap|masscan|rustscan|nuclei|ffuf|gobuster|feroxbuster|nxc|netexec|crackmapexec|hydra|medusa|sqlmap|wpscan|nikto|dirb)\b", re.I)
# output-hygiene: an `echo "=== label ==="` (or ###) decorative section-header banner. CLAUDE.md forbids
# these (pure token noise; the harness already shows each command with its own output). Fires regardless
# of engagement. Matches inside a vm.sh single-quoted wrapper too (the banner text is still in the command).
ECHO_BANNER = re.compile(r"""echo\s+["'][^"'\n]*(?:={3,}|#{3,})""", re.I)


def ip_out_of_scope(cmd, sc):
    cidrs = []
    for o in sc.get("out_of_scope", []):
        o = o.strip()
        try:
            cidrs.append(ipaddress.ip_network(o, strict=False))
        except ValueError:
            pass
    if not cidrs:
        return []
    hits = []
    for tok in IP_RE.findall(cmd):
        try:
            ip = ipaddress.ip_address(tok)
        except ValueError:
            continue
        if any(ip in c for c in cidrs):
            hits.append(tok)
    return hits


def _enforcing():
    """Enforcement is ON unless an escape-hatch marker sits in the hooks dir. Creating
    `skills/hooks/.enforce-off` (== HERE) downgrades every deny to an advisory warning."""
    return not os.path.exists(os.path.join(HERE, ".enforce-off"))


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

    deny = []   # deterministic, block-worthy reasons (one line each)

    # output-hygiene (engagement-independent): echo "=== ... ===" section-header banners.
    if ECHO_BANNER.search(cmd):
        deny.append("output-banner: drop the `echo \"=== ... ===\"` section-header (CLAUDE.md forbids "
                    "it: pure token noise; the harness already shows each command's own output). Run "
                    "the command directly.")

    # scope / RoE (only when an engagement is active)
    try:
        import _engagement
        d = _engagement.active_dir()
        if d:
            sc = _engagement.scope(d)
            # out-of-scope targets: exact host/domain match + IP-in-CIDR
            flagged = set(ip_out_of_scope(cmd, sc))
            for host in HOST_RE.findall(cmd):
                if host.rsplit(".", 1)[-1].lower() in FILE_EXT:
                    continue   # config.yml / app.py are filenames, not hosts
                if _engagement.out_of_scope_match(host, sc):
                    flagged.add(host)
            if flagged:
                deny.append("out-of-scope: command targets " + ", ".join(sorted(flagged))
                            + " which match an OUT-OF-SCOPE entry in scope.md")
            # RoE tooling
            if sc.get("no_bruteforce") and BRUTEFORCE.search(cmd):
                deny.append("RoE no_bruteforce: command uses brute-force tooling")
            if sc.get("no_dos") and DOS.search(cmd):
                deny.append("RoE no_dos: command looks like high-volume/DoS tooling")
            if sc.get("passive_only") and ACTIVE.search(cmd):
                deny.append("RoE passive_only: command runs an active scanner")
    except Exception:
        pass

    if not deny:
        return
    body = "\n- ".join(deny)
    # telemetry: every block/advise is a recorded drift signal (a wrong action the guard caught)
    try:
        import _telemetry
        reason = ("blocked " if _enforcing() else "advised ") + " | ".join(x.split(":")[0] for x in deny)
        _telemetry.drift("scope-guard", reason)
        _telemetry.hook("scope-guard", action=("deny" if _enforcing() else "advise"))
    except Exception:
        pass
    if _enforcing():
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": ("BLOCKED by harness enforcement:\n- " + body
                + "\n\nFix the command and re-run. (False block? create skills/hooks/.enforce-off "
                  "to downgrade enforcement to advisory.)"),
        }}))
    else:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "SCOPE/RoE/HYGIENE (advisory; enforcement OFF via .enforce-off):\n- " + body,
        }}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
