#!/usr/bin/env python3
"""idor-sweep: Burp-driven two-account + ID-variant IDOR check (six2dez distillation).

Parses a raw Burp request (the OWNER's, with their auth + a numeric object ID), builds an
owner-baseline / idor-test (attacker auth, same id) / id+-N enum set, sends each through Burp
send_http1_request over the bridge, and prints a verdict. Scope/RoE fail-closed via scope.md.

Usage:
  idor-sweep.py [--dry-run] <eng> <reqfile> [--attacker-auth "Cookie: session=B"]
                [--id-regex '/orders/(\\d+)'] [--range N] [--port P] [--https|--no-https]
Env: VAULT (targets/ root), VM_SH (bridge, default /root/vm.sh).
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(SCRIPT_DIR))  # scripts/burp/ -> repo root
VAULT = os.environ.get("VAULT") or REPO
VM_SH = os.environ.get("VM_SH", "/root/vm.sh")
sys.path.insert(0, os.path.join(REPO, "skills", "hooks"))
import _engagement  # canonical scope.md parser

DEFAULT_ID_RES = [r"/(\d+)(?:/|\?|$)", r"[?&]id=(\d+)"]


def parse_request(text):
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = head.split("\n")
    parts = lines[0].split()
    method, path = (parts + ["", ""])[0], (parts + ["", ""])[1]
    headers, host = [], ""
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
            if k.strip().lower() == "host":
                host = v.strip()
    return {"method": method, "path": path, "host": host.split(":")[0], "headers": headers, "body": body}


def find_id(path, id_regex=None):
    for p in ([id_regex] if id_regex else DEFAULT_ID_RES):
        m = re.search(p, path)
        if m:
            return int(m.group(1)), m.span(1)
    return None


def sub_id(path, span, newid):
    return path[:span[0]] + str(newid) + path[span[1]:]


def swap_auth(headers, attacker_auth):
    if attacker_auth:
        an, av = attacker_auth.split(":", 1)
        an, av = an.strip(), av.strip()
        out = [(k, v) for (k, v) in headers if k.lower() != an.lower()]
        out.append((an, av))
        return out
    return [(k, v) for (k, v) in headers if k.lower() not in ("cookie", "authorization")]


def build_set(req, idinfo, attacker_auth, rng):
    cur, span = idinfo
    atk = swap_auth(req["headers"], attacker_auth)
    out = [{"label": "owner-baseline", "id": cur, "path": req["path"], "headers": req["headers"]},
           {"label": "idor-test", "id": cur, "path": req["path"], "headers": atk}]
    for k in range(1, rng + 1):
        for nid in (cur - k, cur + k):
            if nid < 0 or nid == cur:
                continue
            out.append({"label": "enum", "id": nid, "path": sub_id(req["path"], span, nid), "headers": atk})
    return out


def host_in_scope(host, in_scope):
    host = (host or "").lower().strip()
    return any(_engagement._scope_entry_match(host, (e or "").lower().strip(), strict=True)
               for e in in_scope)


def _die(msg, code=2):
    print("idor-sweep: " + msg, file=sys.stderr)
    sys.exit(code)


def verdict(resps):
    owner = next(r for r in resps if r["label"] == "owner-baseline")
    idor = next(r for r in resps if r["label"] == "idor-test")
    enum = [r for r in resps if r["label"] == "enum"]
    out = {"owner_status": owner["status"]}
    if not (200 <= owner["status"] < 300):
        out["idor"] = "WARN: baseline not 2xx (stale session / wrong request?)"
    elif 200 <= idor["status"] < 300 and (
            idor["hash"] == owner["hash"]
            or abs(idor["length"] - owner["length"]) <= 0.05 * max(owner["length"], 1)):
        out["idor"] = "LIKELY IDOR"
    elif idor["status"] in (401, 403, 404) or idor["length"] == 0:
        out["idor"] = "authorization enforced"
    else:
        out["idor"] = "inconclusive (status %d)" % idor["status"]
    out["enum_accessible"] = sum(1 for r in enum if 200 <= r["status"] < 300)
    out["enum_total"] = len(enum)
    return out


def _raw(reqd, meta):
    """Build the raw HTTP/1.1 request text for one request dict."""
    lines = ["%s %s HTTP/1.1" % (meta["method"], reqd["path"])]
    lines += ["%s: %s" % (k, v) for (k, v) in reqd["headers"]]
    return "\r\n".join(lines) + "\r\n\r\n"


def run_live(meta):
    """Send every request via Burp send_http1_request in ONE VM-side python; parse status+len+hash."""
    payload = {"host": meta["host"], "port": meta["port"], "https": meta["https"],
               "reqs": [{"label": r["label"], "id": r["id"], "raw": _raw(r, meta)} for r in meta["requests"]]}
    b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    vm_py = r'''
import base64, json, os, re, hashlib, subprocess
cli = os.path.expanduser("~/burp-mcp-cli.py")
P = json.loads(base64.b64decode("%s").decode())
def send(raw):
    args = json.dumps({"content": raw, "targetHostname": P["host"], "targetPort": P["port"],
                       "usesHttps": P["https"]})
    try:
        out = subprocess.run(["python3", cli, "call", "send_http1_request", args],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception:
        return (0, 0, "")
    # Live-verified 2026-07-27 (bridge call, real target): the return is a Java toString() blob
    # "HttpRequestResponse{httpRequest=<raw req>, httpResponse=<raw resp>, messageAnnotations=...}".
    # Two traps a naive "first HTTP/x.y match" + "first \r\n\r\n split" both fall into:
    #  1. header values contain commas (Date/Allow), so slicing on ", " is unsafe -> slice by the
    #     httpResponse=/messageAnnotations= markers instead.
    #  2. subprocess.run(text=True) applies universal-newline decoding, so by the time `out` is a
    #     str the wire's \r\n is already bare \n -> split on "\n\n", not "\r\n\r\n".
    i = out.find("httpResponse=")
    if i == -1:
        return (0, 0, "")
    resp = out[i + len("httpResponse="):]
    j = resp.rfind(", messageAnnotations=")
    if j != -1:
        resp = resp[:j]
    m = re.search(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", resp)
    status = int(m.group(1)) if m else 0
    body = resp.split("\n\n", 1)[-1] if "\n\n" in resp else resp
    return (status, len(body), hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()[:16])
res = []
for r in P["reqs"]:
    s, ln, h = send(r["raw"])
    res.append({"label": r["label"], "id": r["id"], "status": s, "length": ln, "hash": h})
print(json.dumps(res))
''' % b64
    py_b64 = base64.b64encode(vm_py.encode()).decode()
    cmd = "echo '%s' | base64 -d > /tmp/idor_sweep_send.py; python3 /tmp/idor_sweep_send.py" % py_b64
    r = subprocess.run(["bash", VM_SH, cmd], capture_output=True, text=True, timeout=180)
    try:
        resps = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        print("idor-sweep: bridge send failed -> %s%s" % (r.stdout[-300:], r.stderr[-300:]), file=sys.stderr)
        return 1
    v = verdict(resps)
    print("id | label | status | len | ")
    for x in resps:
        print("%s | %s | %s | %s" % (x["id"], x["label"], x["status"], x["length"]))
    print("\nVERDICT: %s  (baseline %s; %d/%d enum neighbors accessible)" % (
        v["idor"], v["owner_status"], v["enum_accessible"], v["enum_total"]))
    if v["idor"] == "LIKELY IDOR":
        print("PoC it:  scripts/capture.sh burp %s idor-%s %s %s %s %s %s" % (
            meta["eng"], meta["host"], meta["host"], meta["port"], str(meta["https"]).lower(),
            meta["method"], meta["requests"][0]["path"]))
        print("Then scaffold a FIND per hunt-idor (never auto-written).")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="idor-sweep.py")
    ap.add_argument("eng")
    ap.add_argument("reqfile")
    ap.add_argument("--attacker-auth")
    ap.add_argument("--id-regex")
    ap.add_argument("--range", type=int, default=3)
    ap.add_argument("--port", type=int)
    ap.add_argument("--https", action="store_true", default=None)
    ap.add_argument("--no-https", dest="https", action="store_false")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.attacker_auth and ":" not in a.attacker_auth:
        _die("--attacker-auth must be 'Name: value' (got %r)" % a.attacker_auth)

    d = os.path.join(VAULT, "targets", a.eng)
    if not os.path.isdir(d):
        _die("no engagement dir %s" % d)
    sc = _engagement.scope(d)
    if sc.get("passive_only"):
        _die("passive_only is set in scope.md; idor-sweep is an ACTIVE test, refusing")
    if not sc["in_scope"]:
        _die("scope.md has no in_scope entries; add the target before running idor-sweep (active tool)")
    try:
        req = parse_request(open(a.reqfile, encoding="utf-8", errors="ignore").read())
    except OSError as e:
        _die("cannot read reqfile: %s" % e)
    if not host_in_scope(req["host"], sc["in_scope"]):
        _die("target host %r not in scope.md in_scope; refusing" % req["host"])
    idinfo = find_id(req["path"], a.id_regex)
    if not idinfo:
        _die("no numeric id found in path %r (use --id-regex)" % req["path"])
    rng = 0 if sc.get("no_bruteforce") else max(0, a.range)
    reqset = build_set(req, idinfo, a.attacker_auth, rng)

    https = a.https if a.https is not None else True
    port = a.port if a.port else (443 if https else 80)
    meta = {"host": req["host"], "port": port, "https": https, "method": req["method"],
            "no_bruteforce": bool(sc.get("no_bruteforce")), "requests": reqset, "eng": a.eng}
    if a.dry_run:
        print(json.dumps(meta, indent=2))
        return 0
    return run_live(meta)   # live send + verdict; the function body is added in Task 2


if __name__ == "__main__":
    sys.exit(main())
