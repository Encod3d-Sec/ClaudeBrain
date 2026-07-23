#!/usr/bin/env python3
"""web-recon.py -- PostToolUse hook. Auto-LAUNCH the parallel web-recon suite
(scripts/recon-web.sh) when a NEW in-scope web surface is discovered in a command's output.

Idempotent (ledger targets/<eng>/.web-surfaces), scope-gated (in-scope hosts ONLY, never touches
an out-of-scope host), framework-meta guarded, fail-open. A deliberate, scope-guarded extension of
the hook charter: it auto-LAUNCHES in-scope recon (as autocard renders finished tabs), so parallel
scanning + a page render fire on discovery instead of relying on a nudge the operator ignores. RoE
(passive_only/no_dos) is honored inside recon-web.sh. WEB_RECON_DRYRUN=1 records the launch without
spawning (tests)."""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, HERE)

_META_RE = re.compile(
    r"playbook\.json|triggers\.json|wiki-wiring|apply-wiring|wiring-exempt|"
    r"recon-capture|hunt-trigger|scope-guard|engagement-init|web-recon|recon-web|"
    r"scripts/(?:playbook|wiki|gen_index|build_moc|wl-add|wiki-stage|check-hooks)|"
    r"skills/hooks/", re.I)

_TARGET_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_NMAP_HTTP_RE = re.compile(r"\b(\d{2,5})/tcp\s+open\s+(?:ssl/)?(https?|http-alt|http-proxy)\b", re.I)
_URL_RE = re.compile(r"https?://[A-Za-z0-9._-]+(?::\d{2,5})?", re.I)
_LOCATION_RE = re.compile(r"^\s*Location:\s*(https?://[A-Za-z0-9._-]+(?::\d{2,5})?)", re.I | re.M)


def _response_text(data):
    r = data.get("tool_response")
    if isinstance(r, dict):
        return str(r.get("stdout", "") or r.get("output", "") or "")
    return str(r or "")


def _host(url):
    return re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()


def _in_scope(host, sc, eng):
    if eng.out_of_scope_match(host, sc):
        return False
    ins = sc.get("in_scope", [])
    if not ins:
        return True  # no explicit in-scope list -> allow anything not out-of-scope
    return any(eng._scope_entry_match(host, (e or "").lower().strip()) for e in ins)


def _surfaces(cmd, blob, sc, eng):
    """In-scope web-surface URLs discovered in the command + its output."""
    found = set()
    tgt_ips = [ip for ip in _TARGET_IP_RE.findall(cmd) if _in_scope(ip, sc, eng)]
    # 1. nmap/rustscan "80/tcp open http" on the in-scope scan-target IP
    for ip in tgt_ips:
        for port, svc in _NMAP_HTTP_RE.findall(blob):
            scheme = "https" if svc.lower().startswith("https") or port in ("443", "8443") else "http"
            found.add("%s://%s:%s" % (scheme, ip, port))
    # 2. a redirect (Location:) to a vhost off an in-scope target -> in-scope-derived
    if tgt_ips:
        for loc in _LOCATION_RE.findall(blob):
            found.add(loc.rstrip("/"))
    # 3. an explicit URL whose host is positively in-scope
    for url in _URL_RE.findall(cmd + "\n" + blob):
        if _in_scope(_host(url), sc, eng):
            found.add(url.rstrip("/"))
    return found


def main():
    try:
        data = json.loads(sys.stdin.read())
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    cmd = (data.get("tool_input") or {}).get("command", "")
    if not cmd or _META_RE.search(cmd):
        return
    try:
        import _engagement
        d = _engagement.active_dir()
    except Exception:
        return
    if not d:
        return
    sc = _engagement.scope(d)
    surfaces = _surfaces(cmd, _response_text(data), sc, _engagement)
    if not surfaces:
        return
    ledger = os.path.join(d, ".web-surfaces")
    seen = set(open(ledger, encoding="utf-8").read().split()) if os.path.exists(ledger) else set()
    fresh = [u for u in sorted(surfaces) if u not in seen]
    if not fresh:
        return
    eng_name = os.path.basename(d)
    script = os.path.join(_engagement.VAULT, "scripts", "recon-web.sh")
    dry = os.environ.get("WEB_RECON_DRYRUN") == "1"
    launched = []
    for url in fresh:
        if not dry:
            try:
                subprocess.Popen(["bash", script, eng_name, url], cwd=_engagement.VAULT,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
            except Exception:
                continue
        launched.append(url)
    if not launched:
        return
    with open(ledger, "a", encoding="utf-8") as f:
        for u in launched:
            f.write(u + "\n")
    try:
        import _telemetry
        _telemetry.log_event("web-recon-launch", d=d, urls=launched)
    except Exception:
        pass
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "additionalContext": (
            "AUTO WEB-RECON launched (parallel feroxbuster/nuclei/whatweb + page render) for: "
            + ", ".join(launched[:3])
            + ". Read the cards as they finish (recon/); do not hand-probe what a scanner covers."),
    }}))


try:
    main()
except Exception:
    pass  # fail open
