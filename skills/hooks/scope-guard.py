#!/usr/bin/env python3
"""PreToolUse(Bash) hook: advisory scope + RoE guard.

Before a shell command runs, warn (does NOT block) when it appears to:
  - target an out-of-scope host/IP (exact host/domain match or IP-in-CIDR), or
  - use tooling forbidden by the engagement RoE flags
    (no_bruteforce / no_dos / passive_only in scope.md).

Advisory only: injects additionalContext so the model reconsiders; never denies,
to avoid false-positive lockouts. No active engagement -> silent.
Non-fatal: any error exits 0 silent.
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

    try:
        import _engagement
        d = _engagement.active_dir()
        if not d:
            return
        sc = _engagement.scope(d)
    except Exception:
        return

    warns = []

    # out-of-scope targets: exact host/domain match + IP-in-CIDR
    flagged = set(ip_out_of_scope(cmd, sc))
    for host in HOST_RE.findall(cmd):
        if host.rsplit(".", 1)[-1].lower() in FILE_EXT:
            continue   # config.yml / app.py are filenames, not hosts
        if _engagement.out_of_scope_match(host, sc):
            flagged.add(host)
    if flagged:
        warns.append("targets " + ", ".join(sorted(flagged)) + " which match an OUT-OF-SCOPE entry in scope.md")

    # RoE tooling
    if sc.get("no_bruteforce") and BRUTEFORCE.search(cmd):
        warns.append("uses brute-force tooling but RoE is no_bruteforce")
    if sc.get("no_dos") and DOS.search(cmd):
        warns.append("looks like high-volume/DoS tooling but RoE is no_dos")
    if sc.get("passive_only") and ACTIVE.search(cmd):
        warns.append("runs an active scanner but RoE is passive_only")

    msgs = []
    if warns:
        msgs.append("SCOPE/RoE ADVISORY - this command " + "; and ".join(warns)
                    + ". Re-check targets/<eng>/scope.md before running; proceed only if authorised.")
    if not msgs:
        return
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "\n\n".join(msgs),
        }
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
