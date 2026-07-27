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
    host = host.lower()
    for e in in_scope:
        e = e.strip().lower().split("/")[0]  # ignore CIDR suffix for a host compare
        if host == e or host.endswith("." + e):
            return True
    return False


def _die(msg, code=2):
    print("idor-sweep: " + msg, file=sys.stderr)
    sys.exit(code)


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

    d = os.path.join(VAULT, "targets", a.eng)
    if not os.path.isdir(d):
        _die("no engagement dir %s" % d)
    sc = _engagement.scope(d)
    if sc.get("passive_only"):
        _die("passive_only is set in scope.md; idor-sweep is an ACTIVE test, refusing")
    try:
        req = parse_request(open(a.reqfile, encoding="utf-8", errors="ignore").read())
    except OSError as e:
        _die("cannot read reqfile: %s" % e)
    if sc["in_scope"] and not host_in_scope(req["host"], sc["in_scope"]):
        _die("target host %r not in scope.md in_scope; refusing" % req["host"])
    idinfo = find_id(req["path"], a.id_regex)
    if not idinfo:
        _die("no numeric id found in path %r (use --id-regex)" % req["path"])
    rng = 0 if sc.get("no_bruteforce") else max(0, a.range)
    reqset = build_set(req, idinfo, a.attacker_auth, rng)

    https = a.https if a.https is not None else True
    port = a.port if a.port else (443 if https else 80)
    meta = {"host": req["host"], "port": port, "https": https, "method": req["method"],
            "no_bruteforce": bool(sc.get("no_bruteforce")), "requests": reqset}
    if a.dry_run:
        print(json.dumps(meta, indent=2))
        return 0
    return run_live(meta)   # live send + verdict; the function body is added in Task 2


if __name__ == "__main__":
    sys.exit(main())
