#!/usr/bin/env python3
"""Minimal stdio-free CLI for the local Burp Suite MCP server (SSE at 127.0.0.1:9876).

Drives authenticated/proxied HTTP through Burp from the shell (used when Burp MCP is
not directly reachable as a tool). Usage:
  python3 scripts/burp/burp-mcp-cli.py list                       # list every tool + one-line description
  python3 scripts/burp/burp-mcp-cli.py schema <toolName>          # print a tool's input schema
  python3 scripts/burp/burp-mcp-cli.py call   <toolName> '<json>' # call a tool with JSON args

Override the endpoint with BURP_MCP_URL (default http://127.0.0.1:9876) when the
SSE port is SSH-forwarded from the Kali host (e.g. ssh -L 9876:127.0.0.1:9876).
"""
import urllib.request, json, threading, queue, time, sys, os
BASE=os.environ.get("BURP_MCP_URL", "http://127.0.0.1:9876").rstrip("/")
q=queue.Queue(); endpoint=[None]
def reader():
    r=urllib.request.urlopen(urllib.request.Request(BASE+"/", headers={"Accept":"text/event-stream"}), timeout=60); ev=None
    for raw in r:
        line=raw.decode("utf-8","replace").rstrip("\n")
        if line.startswith("event:"): ev=line[6:].strip()
        elif line.startswith("data:"):
            d=line[5:].strip()
            if ev=="endpoint": endpoint[0]=d
            else:
                try: q.put(json.loads(d))
                except Exception: pass
        elif line=="": ev=None
threading.Thread(target=reader,daemon=True).start()
for _ in range(80):
    if endpoint[0]: break
    time.sleep(0.1)
ep=endpoint[0]
if ep is None: sys.exit("burp-mcp-cli: no MCP SSE endpoint from %s within 8s (is the Burp MCP server running?)" % BASE)
ep = BASE+ep if ep.startswith("/") else (BASE+"/"+ep if ep.startswith("?") else ep)
def post(o):
    urllib.request.urlopen(urllib.request.Request(ep, data=json.dumps(o).encode(), headers={"Content-Type":"application/json"}), timeout=15).read()
def wait(i,t=25):
    end=time.time()+t
    while time.time()<end:
        try: m=q.get(timeout=t)
        except queue.Empty: break
        if m.get("id")==i: return m
    return None
post({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"cc","version":"1"}}})
wait(1); post({"jsonrpc":"2.0","method":"notifications/initialized"})
mode=sys.argv[1] if len(sys.argv)>1 else "list"
if mode=="list":
    post({"jsonrpc":"2.0","id":2,"method":"tools/list"}); r=wait(2) or {}
    for t in r.get("result",{}).get("tools",[]):
        desc=(t.get("description") or "").strip().splitlines()
        print("%-34s %s" % (t.get("name",""), desc[0] if desc else ""))
elif mode=="schema":
    post({"jsonrpc":"2.0","id":2,"method":"tools/list"}); r=wait(2) or {}
    for t in r.get("result",{}).get("tools",[]):
        if t.get("name")==sys.argv[2]:
            print(json.dumps(t.get("inputSchema",{}),indent=2))
elif mode=="call":
    args=json.loads(sys.argv[3]) if len(sys.argv)>3 else {}
    post({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":sys.argv[2],"arguments":args}})
    r=wait(3,40) or {}
    res=r.get("result",{})
    if "content" in res:
        for c in res["content"]:
            print(c.get("text", json.dumps(c)))
    else:
        print(json.dumps(r,indent=2)[:4000])
