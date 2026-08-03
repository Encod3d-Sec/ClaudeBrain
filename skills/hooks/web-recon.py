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

_CF_RE = re.compile(r"^\s*(?:server:\s*cloudflare|cf-ray:\s*\S+)", re.I | re.M)
_SERVER_RE = re.compile(r"^\s*server:\s*(\S+)", re.I | re.M)


def _blob_host_spans(blob):
    """(position, host) for every URL literal found in blob, in appearance order. Used to
    tell whether a shared tool-output blob carries evidence for one host or several."""
    return [(m.start(), _host(m.group(0))) for m in _URL_RE.finditer(blob)]


def _attributed_blob(blob, host, hosts):
    """The slice of blob that is trustworthy evidence for `host`, or '' when it cannot be
    trusted at all for this invocation. `hosts` is every host being judged in the current
    invocation (all of `fresh`), so this function can tell "one surface" from "several".

    - len(hosts) <= 1 (a single-surface invocation): the whole blob is unambiguous by
      construction, even when it carries no URL literal at all -- a plain `curl -sI`
      response never echoes its own request URL, yet there is only one surface this
      command's output could possibly be about. Use it as-is. This is the case the six
      pre-existing tests rely on.
    - len(hosts) > 1 (a multi-surface invocation, e.g. concatenated httpx/nmap/chained-curl
      output covering several targets in one command): header evidence is trustworthy ONLY
      when the blob's own URL literals disambiguate EVERY host in `hosts`, not merely the
      one being asked about right now. A blob with no literals at all (the common shape of
      `curl -sI a ; curl -sI b`, which never echoes either URL), or literals for only some
      of the hosts, proves nothing about which lines belong to which surface -- it is
      UNATTRIBUTABLE for ALL of them. Trusting "the one host we happen to be able to
      locate" here is exactly the cross-host leak this function exists to prevent.
    """
    if len(hosts) <= 1:
        return blob
    spans = _blob_host_spans(blob)
    span_hosts = {h for _, h in spans}
    if not hosts <= span_hosts:
        return ""  # blob doesn't literally name every host in this invocation
    start = next((p for p, h in spans if h == host), None)
    if start is None:
        return ""  # this host isn't attributable at all in a multi-host blob
    end = next((p for p, h in spans if p > start and h != host), len(blob))
    return blob[start:end]


def _cf_verdict(blob, url, hosts=frozenset()):
    """"cf" | "clear" | "unknown" -- is this surface fronted by Cloudflare?

    `hosts` is every host being judged in the current invocation (all of `fresh`); an
    empty/singleton set means this url is the only surface in play. Header evidence
    already present in the tool output is authoritative and free, but ONLY when it can be
    attributed to THIS url's host (see _attributed_blob): an unattributable multi-host
    blob skips BOTH header checks entirely -- it never decides "cf" OR "clear" from blob
    text for any host in that invocation -- and falls straight through to the bounded
    per-host probe. Under DRYRUN (the test path), or if the probe fails/is unreachable,
    the result is "unknown".
    """
    host = _host(url)
    scoped = _attributed_blob(blob, host, hosts or {host})
    if scoped:
        if _CF_RE.search(scoped):
            return "cf"
        if _SERVER_RE.search(scoped):
            return "clear"
    if os.environ.get("WEB_RECON_DRYRUN") == "1":
        return "unknown"
    try:
        out = subprocess.run(["curl", "-sI", "-m", "3", url], capture_output=True,
                             text=True, timeout=6).stdout
    except Exception:
        return "unknown"
    if _CF_RE.search(out):
        return "cf"
    return "clear" if _SERVER_RE.search(out) else "unknown"


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
    launched, blocked, held = [], [], []
    force = os.environ.get("WEB_RECON_FORCE") == "1"
    blob = _response_text(data)
    hosts_in_play = {_host(u) for u in fresh}
    for url in fresh:
        host = _host(url)
        verdict = _cf_verdict(blob, url, hosts_in_play)
        if not force and verdict == "cf":
            blocked.append(url)
            continue
        # A multi-host invocation where the blob carries server/cf-ray evidence
        # SOMEWHERE but could not attribute ANY of it to this host (verdict fell all the
        # way through to "unknown" with no live probe to back it, e.g. WEB_RECON_DRYRUN
        # or a chained plain `curl -sI ...; curl -sI ...` that never echoes either URL)
        # is NOT the same situation as an honest single-host "no evidence at all" -- that
        # is precisely the cross-host bypass shape this hook exists to close. Hold rather
        # than launch; a later turn with disambiguating output, or a live (non-DRYRUN)
        # probe, resolves it. Gated on the raw blob actually carrying SOME header
        # evidence: a multi-surface invocation whose blob has none at all (e.g. an
        # nmap-derived target plus its own redirect destination, port-state text only)
        # has nothing that could leak across hosts, so it stays on the ordinary
        # "unknown launches" path -- this is what test_launches_on_inscope_redirect_vhost
        # relies on.
        if not force and verdict == "unknown" and len(hosts_in_play) > 1 \
                and not _attributed_blob(blob, host, hosts_in_play) \
                and (_CF_RE.search(blob) or _SERVER_RE.search(blob)):
            held.append(url)
            continue
        if not dry:
            try:
                subprocess.Popen(["bash", script, eng_name, url], cwd=_engagement.VAULT,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
            except Exception:
                continue
        launched.append(url)
    # Ledger launched + blocked only: a confirmed surface (launched or CF-suppressed) must
    # not be re-probed on every later turn. A held (ambiguous) surface stays OFF the ledger
    # on purpose, so it gets a fresh, potentially disambiguating look on the next turn.
    if launched or blocked:
        with open(ledger, "a", encoding="utf-8") as f:
            for u in launched + blocked:
                f.write(u + "\n")
    # One additionalContext per hook invocation (mirrors recon-capture.py's _emit(blocks)):
    # a mixed-verdict run (some blocked, some held, some launched) must not print several
    # separate JSON objects.
    blocks = []
    if blocked:
        blocks.append(
            "CLOUDFLARE detected -- auto web-recon SUPPRESSED for: "
            + ", ".join(blocked[:3])
            + ". Scanners produce block-page artifacts here and risk a 1020 hard deny. "
              "Enumerate by READING the application's own JS bundle instead. "
              "WEB_RECON_FORCE=1 overrides.")
    if held:
        blocks.append(
            "AMBIGUOUS multi-host output -- auto web-recon HELD (not launched) for: "
            + ", ".join(held[:3])
            + ". Server headers in this shared output could not be attributed to a "
              "specific host, so none of the candidates were scanned (one may be "
              "Cloudflare-fronted). Re-run with per-host output, or let a live probe "
              "resolve it. WEB_RECON_FORCE=1 overrides.")
    if launched:
        try:
            import _telemetry
            _telemetry.log_event("web-recon-launch", d=d, urls=launched)
        except Exception:
            pass
        blocks.append(
            "AUTO WEB-RECON launched (parallel feroxbuster/nuclei/whatweb + page render) for: "
            + ", ".join(launched[:3])
            + ". Read the cards as they finish (recon/); do not hand-probe what a scanner covers.")
    if blocks:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n\n".join(blocks),
        }}))


try:
    main()
except Exception:
    pass  # fail open
