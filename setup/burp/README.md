# setup/burp/

Kali-box setup steps for the Burp integration. The Burp **driver** layer lives in
`scripts/burp/` (`burp-mcp-cli.py` bridge, `burp-transport.sh` resolver,
`burp-scope-sync.py`); the **skills** live in `skills/burp/` (`hunt-burp`,
`screenshot-burp`). This folder holds the one-time host setup that those depend on.

| Step | What | When |
|------|------|------|
| `disable-lock.sh` | Permanently disable the Kali seat lock + screen blank so GUI automation (`capture.sh burp`, xdotool driving Burp) never has synthetic input routed to a locker. | Once per Kali box (re-run after a rebuild). |

Full Burp MCP install (the "MCP Server" BApp, native vs bridge transport, the BApp
loadout) is documented in `wiki/tools/burp-mcp.md`. The seat-lock gotcha is in
`docs/setup.md`.

**Goal of this namespace:** grow the harness's Burp interactiveness here, custom
driver features in `scripts/burp/`, their host prerequisites in `setup/burp/`, the
methodology/skills in `skills/burp/`, so the Burp layer stays cleanly separable.
