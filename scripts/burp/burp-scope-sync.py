#!/usr/bin/env python3
"""burp-scope-sync: push the engagement's scope.md into Burp's project scope over the MCP.

WHY: the Burp MCP extension AUTO-APPROVES requests whose target is IN Burp's scope (verified live
2026-07-24: an in-scope `send_http1_request` flows; an out-of-scope one hangs on the GUI approval
prompt a headless seat cannot answer). So syncing engagement scope -> Burp scope makes IN-SCOPE native
`mcp__burp__send_*` calls work headless, while out-of-scope sends stay gated (safe default). It also
closes a real blind spot: `scope-guard.py` is PreToolUse(Bash) only, so native MCP sends bypass it
entirely -- Burp's in-scope==auto-approve becomes the scope gate on that path.

Scope entries become Burp advanced-scope host regexes: IPs and domains PRECISELY; only octet-aligned
IPv4 CIDRs (/8,/16,/24) get a prefix regex. Non-aligned CIDRs / IPv6 CIDRs are SKIPPED (fail-closed:
those sends just need a one-time manual MCP-tab approval; we never widen scope to over-approve).

Usage:
  burp-scope-sync.py [<eng>]            # sync the active (or named) engagement's scope into Burp
  burp-scope-sync.py --dry-run [<eng>]  # print the Burp scope JSON, do NOT push (offline)
Env: VAULT (targets/ root, self-locates to repo), VM_SH (SSH bridge, default /root/vm.sh).
"""
import base64
import ipaddress
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
import _engagement  # canonical scope.md parser (same source of truth as scope-guard.py)


def host_to_regex(entry):
    """One scope.md entry -> a Burp advanced-scope host regex (anchored), or None to SKIP (fail-closed)."""
    entry = entry.strip()
    if "/" in entry and not entry.startswith(("http://", "https://")):
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return None
        if net.version != 4 or net.prefixlen % 8 != 0:
            return None  # IPv6 CIDR or non-octet-aligned mask: skip rather than over-approve
        octets = str(net.network_address).split(".")[: net.prefixlen // 8]
        return "^" + "".join(re.escape(o) + r"\." for o in octets)  # e.g. 10.112.0.0/16 -> ^10\.112\.
    try:
        ipaddress.ip_address(entry)
        return "^" + re.escape(entry) + "$"
    except ValueError:
        pass
    host = re.sub(r"^https?://", "", entry).split("/")[0].split(":")[0].strip()
    return (r"^(.*\.)?" + re.escape(host) + "$") if host else None


def _entries(lst):
    out = []
    for e in lst:
        rx = host_to_regex(e)
        if rx:
            out.append({"enabled": True, "file": "^/.*", "host": rx, "port": "^.*$", "protocol": "any"})
    return out


def scope_config(in_scope, out_scope):
    inc, exc = _entries(in_scope), _entries(out_scope)
    return {"target": {"scope": {"advanced_mode": True, "include": inc, "exclude": exc}}}


def _push(config):
    """Set Burp project scope over the SSH bridge. set_project_options takes {"json": "<config-str>"};
    the config travels as base64 so no quoting survives three layers (shell -> args json -> config json)."""
    cfg_b64 = base64.b64encode(json.dumps(config).encode()).decode()
    vm_py = (
        "import base64, json, os, subprocess\n"
        "cli = os.path.expanduser('~/burp-mcp-cli.py')\n"
        "cfg = base64.b64decode('%s').decode()\n"
        "args = json.dumps({'json': cfg})\n"
        "p = subprocess.run(['python3', cli, 'call', 'set_project_options', args],\n"
        "                   capture_output=True, text=True, timeout=45)\n"
        "print((p.stdout or p.stderr).strip()[:300])\n"
    ) % cfg_b64
    py_b64 = base64.b64encode(vm_py.encode()).decode()
    cmd = "echo '%s' | base64 -d > /tmp/burp_scope_push.py; python3 /tmp/burp_scope_push.py" % py_b64
    r = subprocess.run(["bash", VM_SH, cmd], capture_output=True, text=True, timeout=90)
    return (r.stdout or "") + (r.stderr or "")


def main():
    argv = sys.argv[1:]
    dry = "--dry-run" in argv
    rest = [a for a in argv if a != "--dry-run"]
    eng = rest[0] if rest else None
    d = os.path.join(VAULT, "targets", eng) if eng else _engagement.active_dir()
    if not d or not os.path.isdir(d):
        print("burp-scope-sync: no engagement (pass <eng> or set targets/active.md)", file=sys.stderr)
        return 2
    sc = _engagement.scope(d)
    in_scope, out_scope = sc["in_scope"], sc["out_of_scope"]
    if not in_scope:
        print("burp-scope-sync: scope.md has no In-scope entries; nothing to sync", file=sys.stderr)
        return 3
    skipped = [e for e in in_scope if not host_to_regex(e)]
    if skipped:
        print("burp-scope-sync: NOT auto-approving (non-octet CIDR / IPv6 / unparseable -> needs a one-time "
              "MCP-tab approval): " + ", ".join(skipped), file=sys.stderr)
    config = scope_config(in_scope, out_scope)
    ninc = len(config["target"]["scope"]["include"])
    if dry:
        print(json.dumps(config, indent=2))
        print("# dry-run: %d in-scope host(s) would be pushed to Burp (of %d entries)"
              % (ninc, len(in_scope)), file=sys.stderr)
        return 0
    out = _push(config)
    if "applied" in out.lower():
        print("burp-scope-sync: pushed %d in-scope host(s) to Burp scope -> in-scope MCP sends now "
              "auto-approve. %s" % (ninc, out.strip()))
        return 0
    print("burp-scope-sync: push may have failed -> %s" % out.strip(), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
