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


_DEFAULT_PORT = {"http": "80", "https": "443"}


def _surface_key(url):
    """THE canonical identity of a real network surface: "scheme://host:port", lowercased,
    with the scheme's default port made explicit (http -> 80, https -> 443).

    This is the ONE key used everywhere CF-attribution identity is computed (blob spans,
    attributed slice, verdict, main()'s in-play set and ledger). Attribution bugs in this
    hook have all been one shape: an identity built by stripping components by hand, so
    two genuinely DIFFERENT real surfaces collapse into one string and the whole shared
    output blob gets trusted for both. Scheme AND port are part of what makes a surface
    real, so both are part of the key:

        https://h  ==  https://h:443     (one surface, spelled two ways)
        http://h   !=  https://h         (plaintext :80 vs the TLS/CDN edge -- two)
        https://h  !=  https://h:8080    (edge vs an alternate origin port -- two)

    Anything unparseable gets its own key (the raw string): over-fragmentation is the SAFE
    failure direction here -- one real surface treated as two only means "hold, launch
    nothing", while two surfaces treated as one is the false-clear that scans a
    Cloudflare-fronted host. When in doubt, fragment.

    NOT a replacement for _host(): scope matching is deliberately keyed on the bare
    hostname (neither scheme nor port changes whether a host is in scope) and keeps using
    _host() unchanged.
    """
    s = url.strip()
    m = re.match(r"^(https?)://", s, re.I)
    if not m:
        return s.lower()  # no scheme to canonicalize -> its own key, never merged
    scheme = m.group(1).lower()
    host, _, port = s[m.end():].split("/")[0].lower().partition(":")
    if not host:
        return s.lower()
    return "%s://%s:%s" % (scheme, host, port or _DEFAULT_PORT[scheme])


def _blob_host_spans(blob):
    """(position, surface key) for every URL literal found in blob, in appearance order.
    Keyed by _surface_key, so two literals differing only by scheme or port are tracked as
    the distinct surfaces they are. Used to tell whether a shared tool-output blob carries
    evidence for one surface or several."""
    return [(m.start(), _surface_key(m.group(0))) for m in _URL_RE.finditer(blob)]


def _attributed_blob(blob, key, keys):
    """The slice of blob that is trustworthy evidence for surface `key`, or '' when it
    cannot be trusted at all for this invocation. `keys` is every real surface this one
    command touched (see main()), so this function can tell "one surface" from "several"
    -- see _surface_key for what counts as one.

    - len(keys) <= 1 (a single-surface invocation): the whole blob is unambiguous by
      construction, even when it carries no URL literal at all -- a plain `curl -sI`
      response never echoes its own request URL, yet there is only one surface this
      command's output could possibly be about. Use it as-is. This is the case the six
      pre-existing tests rely on.
    - len(keys) > 1 (a multi-surface invocation, e.g. concatenated httpx/nmap/
      chained-curl output covering several targets in one command): header evidence is
      trustworthy ONLY when the blob's own URL literals disambiguate EVERY key in `keys`,
      not merely the one being asked about right now. A blob with no literals at all (the
      common shape of `curl -sI a ; curl -sI b`, which never echoes either URL), or
      literals for only some of the keys, proves nothing about which lines belong to which
      surface -- it is UNATTRIBUTABLE for ALL of them. Trusting "the one surface we happen
      to be able to locate" here is exactly the cross-surface leak this function exists to
      prevent.

    Slicing forward from a URL literal assumes the layout "URL, then the headers it
    labels". Some tools emit the reverse ("curl -sI $u; echo $u"), where slicing forward
    would hand each surface the NEXT one's headers -- a false clear. Header evidence
    sitting ahead of the very first URL literal is the tell, and makes the whole blob
    unattributable rather than mis-sliced.
    """
    if len(keys) <= 1:
        return blob
    spans = _blob_host_spans(blob)
    if not keys <= {k for _, k in spans}:
        return ""  # blob doesn't literally name every surface in this invocation
    if _CF_RE.search(blob[:spans[0][0]]) or _SERVER_RE.search(blob[:spans[0][0]]):
        return ""  # headers precede the URL labelling them: forward slicing is wrong here
    start = next((p for p, k in spans if k == key), None)
    if start is None:
        return ""  # this surface isn't attributable at all in a multi-surface blob
    end = next((p for p, k in spans if p > start and k != key), len(blob))
    return blob[start:end]


def _cf_verdict(blob, url, keys=frozenset()):
    """"cf" | "clear" | "unknown" -- is this surface fronted by Cloudflare?

    `keys` is every surface key (see _surface_key) this one command touched; an
    empty/singleton set means this url is the only surface in play. Header evidence already present in the tool output is authoritative and free, but ONLY
    when it can be attributed to THIS url's surface (see _attributed_blob): an
    unattributable multi-surface blob skips BOTH header checks entirely -- it never
    decides "cf" OR "clear" from blob text for any surface in that invocation -- and
    falls straight through to the bounded per-surface probe. Under DRYRUN (the test
    path), or if the probe fails/is unreachable, the result is "unknown".
    """
    key = _surface_key(url)
    scoped = _attributed_blob(blob, key, keys or {key})
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
    # Canonicalize discovered URLs to surface keys ONCE, here: everything downstream
    # (ledger identity, freshness, the in-play set, attribution, the launch target) then
    # speaks the same single identity, instead of each site re-deriving its own by
    # stripping components off a raw URL string. Two spellings of one real surface
    # (https://h, https://h:443) dedupe here; two real surfaces that merely look alike
    # (http://h vs https://h) stay separate.
    surfaces = {_surface_key(u) for u in _surfaces(cmd, _response_text(data), sc, _engagement)}
    if not surfaces:
        return
    ledger = os.path.join(d, ".web-surfaces")
    # Canonicalize on READ as well as write, so an entry written in any older spelling
    # (bare "https://h" for what is now keyed "https://h:443") still suppresses its own
    # surface. A CF-blocked surface that stopped matching its own ledger line would be
    # re-judged from scratch and could launch on a later turn's thinner evidence.
    seen = {_surface_key(u) for u in open(ledger, encoding="utf-8").read().split()} \
        if os.path.exists(ledger) else set()
    fresh = [u for u in sorted(surfaces) if u not in seen]
    if not fresh:
        return
    eng_name = os.path.basename(d)
    script = os.path.join(_engagement.VAULT, "scripts", "recon-web.sh")
    dry = os.environ.get("WEB_RECON_DRYRUN") == "1"
    launched, blocked, held = [], [], []
    force = os.environ.get("WEB_RECON_FORCE") == "1"
    blob = _response_text(data)
    # Every real surface this ONE command touched, by canonical key. A false singleton here
    # is what makes _attributed_blob trust the whole shared blob, so this must count real
    # surfaces, not judged ones: the COMMAND's own URLs are unioned in, including surfaces
    # that never reached `fresh` because they are out of scope or already ledgered. Their
    # responses are still in this blob, and their `server:` line must not decide a verdict
    # for an in-scope surface. Blob literals are deliberately NOT unioned in: a URL in a
    # response header (Location, Link, CSP) is a reference, not a probed surface, and
    # counting those would hold nearly every curl-derived launch, which just trains the
    # operator to run with WEB_RECON_FORCE=1 and lose the gate entirely.
    keys_in_play = set(fresh) | {_surface_key(u) for u in _URL_RE.findall(cmd)}
    for url in fresh:
        verdict = _cf_verdict(blob, url, keys_in_play)
        if not force and verdict == "cf":
            blocked.append(url)
            continue
        # A multi-surface invocation where the blob carries server/cf-ray evidence
        # SOMEWHERE but could not attribute ANY of it to this surface (verdict fell all
        # the way through to "unknown" with no live probe to back it, e.g. WEB_RECON_DRYRUN
        # or a chained plain `curl -sI ...; curl -sI ...` that never echoes either URL)
        # is NOT the same situation as an honest single-surface "no evidence at all" --
        # that is precisely the cross-surface bypass shape this hook exists to close.
        # Hold rather than launch; a later turn with disambiguating output, or a live
        # (non-DRYRUN) probe, resolves it. Gated on the raw blob actually carrying SOME
        # header evidence: a multi-surface invocation whose blob has none at all (e.g. an
        # nmap-derived target plus its own redirect destination, port-state text only)
        # has nothing that could leak across surfaces, so it stays on the ordinary
        # "unknown launches" path -- this is what test_launches_on_inscope_redirect_vhost
        # relies on.
        if not force and verdict == "unknown" and len(keys_in_play) > 1 \
                and not _attributed_blob(blob, url, keys_in_play) \
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
