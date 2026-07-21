---
name: hunt-mcp
description: MCP server attack hunting - tool poisoning, indirect prompt injection via tool output, rug-pull updates, cross-tool shadowing, over-permissioned/excessive-agency tools, lethal trifecta. Wiki-first, FIND schema output.
---

# Hunt: MCP Server Attacks

## Pre-Attack: Wiki Query (MANDATORY)
```
qmd_query "MCP server attacks tool poisoning" via wiki-search MCP -> read mcp-server-attacks if found.
```
Apply documented poisoning/shadowing/rug-pull payloads and the lethal-trifecta model.

**Self-heal:** If the wiki query returns nothing, create a stub `wiki/techniques/web/<slug>.md` (frontmatter + a `## Observed during <engagement>` section built from your findings) before proceeding, so the gap fills instead of silently recurring.

## Scope Check
- Confirm the target MCP server / AI agent is in scope
- Read Deadends.md - skip paths already marked exhausted

## Attack Surface Signals
- Exposed MCP servers, tool manifests, agent tool lists, MCP Inspector (CVE-2025-49596 unauth RCE)
- Tools that fetch untrusted content (web, files, tickets) then feed it back to the model
- Lethal trifecta in one agent: private-data access + untrusted input + an outbound/exfil tool

## Methodology
1. Enumerate tools: name, FULL description/docstring, parameter schema, permissions. The full description is the attack surface, not the UI summary.
2. Map the trifecta across tools (who reads secrets, who reads untrusted input, who can reach network/fs).
3. Tool poisoning: hidden instructions in the description (often `<IMPORTANT>` tags) -> read a secret, pass it via a benign-looking param.
4. Cross-tool shadowing: from one server, hijack a different trusted tool (for example redirect `send_email` recipients).
5. Indirect injection via tool output: plant instructions in a ticket/web page/file the agent will read.
6. Rug pull: get a benign tool approved, then mutate its description server-side after approval.
7. Confirm OOB: data reaching your endpoint, a tool call with attacker-chosen args, or RCE. Not the model's narration.
8. **Distill to wiki (when confirmed):** if the finding is a reusable poisoning, shadowing, or rug-pull technique, stage a GENERIC wiki candidate now (no client host): `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/mcp-server-attacks.md`. Promote later via `scripts/wiki-promote.py`.

## FIND Output

If finding confirmed (OOB action/exfil received, not model narration):
```
Create Vulns/Research/FIND-XXX-SEVERITY-mcp-<server>.md
Add row to Vuln-index.md: | FIND-XXX | MCP <issue> on <server> | <server> | PARTIAL |
Include the poisoned tool/description and the confirmed action or exfil.
Severity: CRITICAL if RCE or secret exfil; HIGH if cross-tool hijack/data exfil; MEDIUM if over-permissioned tool with limited impact
```

If path exhausted:
```
Append to Deadends.md: - [ ] MCP attack on <server> -- no OOB action/exfil, descriptions clean, no trifecta reachable
```

Report: Status + files created.
