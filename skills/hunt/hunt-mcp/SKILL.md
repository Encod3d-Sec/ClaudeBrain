---
name: hunt-mcp
description: MCP server attack hunting - tool poisoning, indirect prompt injection via tool output, rug-pull updates, cross-tool shadowing, over-permissioned/excessive-agency tools, lethal trifecta. Wiki-first, FIND schema output.
---

# Hunt: MCP Server Attacks

**Assumes `hunt-core`** for the scope gate, two-account rule, confirmation gate, enumeration limits, stop conditions, wiki protocol, FIND output, and Deadends. Do not re-derive any of that here.

## Wiki

```
qmd_query "MCP server tool poisoning indirect prompt injection rug pull cross-tool shadowing excessive agency lethal trifecta" via wiki-search MCP
```

Hub: [[web-moc]] (live index). Primary page: [[mcp-server-attacks]].
Anchors: [[llm-attacks]].

## Attack surface

Rank before testing. Not all surfaces are equally reachable or impactful:

- **Tool descriptions / docstrings** - the FULL text (not the UI summary) is the injection surface.
  Hidden instructions ride in `<IMPORTANT>` tags, comments, unicode-tag or zero-width text, and
  parameter descriptions the client concatenates into the model context.
- **Tool output fed back to the model** - any tool that fetches untrusted content (web page, ticket,
  file, email, issue body) and returns it to the model is an indirect-injection channel. Highest
  yield because the payload is not in the manifest and survives description review.
- **Over-permissioned / excessive-agency tools** - a tool that can write files, send mail, run
  shell, or hit arbitrary URLs turns any injection into action. The blast radius, not the bug.
- **Lethal trifecta in one agent** - private-data access + untrusted input + an outbound/exfil
  channel. When all three are reachable by a single agent, injection becomes exfil. Map who holds
  each leg.
- **Exposed MCP infrastructure** - MCP servers, tool manifests, agent tool lists, MCP Inspector
  (CVE-2025-49596, unauth RCE).

## Methodology

1. **Enumerate tools:** name, FULL description/docstring, parameter schema, permissions. The full
   description is the attack surface, not the UI summary.
2. **Map the trifecta across tools** - who reads secrets, who reads untrusted input, who can reach
   network/fs. A single agent holding all three legs is the primary target.
3. **Tool poisoning:** hidden instructions in the description (often `<IMPORTANT>` tags) -> read a
   secret, pass it via a benign-looking param.
4. **Cross-tool shadowing:** from one server, hijack a different trusted tool (for example redirect
   `send_email` recipients).
5. **Indirect injection via tool output:** plant instructions in a ticket/web page/file the agent
   will read.
6. **Rug pull:** get a benign tool approved, then mutate its description server-side after approval.
7. **Confirm** per the Confirmation gate below - demonstrated execution via the client, never the
   model's narration.
8. **Distill when confirmed** - reusable poisoning, shadowing, or rug-pull technique, GENERIC, no
   client host: `python3 scripts/wiki-stage.py --kind technique --slug <slug> --target-page techniques/web/mcp-server-attacks.md`

## Confirmation gate

**NOT confirmation:** a tool description that merely *contains* an injection string; a permissive or
over-broad parameter schema; the trifecta being *reachable* on paper without exercising it across
the tools; the model narrating that it "would" or "could" do something; a payload accepted into a
description or tool output that the client never acted on.

**IS confirmation:** the injection actually **executed via the client** - a shadowed or poisoned
tool invoked with attacker-chosen arguments, private data exfiltrated to your endpoint, or an
unintended action taken by the agent - reproduced in a clean session. For rug-pull, the mutation
took effect on an already-approved tool and the client acted on the new description.

## Chaining

Tool-output injection (step 5) -> **excessive agency**: once you control the model's instructions
via poisoned output, the impact is whatever the over-permissioned tools can do (mail, files, shell,
outbound HTTP). That escalation is prompt-injection territory - hand off to `hunt-llm` for the
injection-to-action payload work, keep the MCP-specific poisoning/shadowing here.

## Evasion

Description review and human approval are the controls to bypass. Hide instructions where a reviewer
skims past: `<IMPORTANT>`/comment blocks, zero-width or unicode-tag characters, whitespace padding,
instructions split across several tools' descriptions, and payloads in parameter descriptions rather
than the top-level docstring. Against approval flows, the rug-pull *is* the evasion: ship benign,
mutate after the human clicks approve.

## Severity

Rated on demonstrated impact, not the presence of a payload.

| Outcome | Typical |
|---|---|
| RCE on the MCP host or client (e.g. MCP Inspector CVE-2025-49596) | critical |
| Secret / credential exfil via poisoned or shadowed tool | critical |
| Cross-tool hijack - arbitrary attacker-controlled tool action | high |
| Data exfil - private context reaching an attacker channel | high |
| Over-permissioned tool, limited demonstrable impact | medium |

## Deadends

```
Append: - [ ] MCP attack on <server> -- no client-side execution; descriptions clean,
              no reachable trifecta, tool output not acted on
```

Record what you tried (poisoning / shadowing / indirect-output / rug-pull), not just that it failed.
