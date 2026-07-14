---
name: wiki-arsenal
description: Fast PARALLEL wiki lookup engine over wiki/techniques + wiki/payloads + wiki/tools + wiki/cheatsheets for a surface/service/vuln-class. Two modes - quick (one qmd search, cheap, fire constantly) and deep (4 parallel subagents, one per area, merged ready-to-use arsenal card, cached). This is the fast path arsenal and the hunt-* skills delegate to. Use for "what do I use against <surface>", "arsenal for <X>", "deep/full arsenal", "tool + payload + technique + cheatsheet for <X>", "fast wiki lookup", "parallel wiki search", any "how do I attack/exploit <service|vuln-class>" where you want the documented tooling + payloads before hand-rolling.
---

# wiki-arsenal

The fast, wiki-first lookup engine for "what do I use against this surface". Runs the four
knowledge areas in parallel so a deep lookup is one wall-clock, not four serial reads. `arsenal`
and the `hunt-*` skills delegate here; never hand-roll from memory when the wiki has the answer.

Input: a surface, service, or vuln-class (e.g. `Jenkins on 8080`, `SSRF`, `Kerberoasting`).

## 0. Cache check first (0 tokens on a repeat)

Slug the surface (lowercase, non-alnum -> `-`). If `targets/<active-eng>/arsenal/<slug>.md`
exists, read and return it. Do not re-spend. (`<active-eng>` = the dir named in `targets/active.md`.)

## Mode: quick (DEFAULT - fire it constantly)

One `mcp__wiki-search__qmd_query` over the whole index (add a `qmd_search` keyword pass when the
surface is an exact product/CVE string). Group the hits under the four areas and return each as
`path -> one-line snippet`:

- **Techniques** (`wiki/techniques/`)
- **Payloads** (`wiki/payloads/`)
- **Tools** (`wiki/tools/`)
- **Cheatsheets** (`wiki/cheatsheets/`)

Cost ~1-2k tokens, no subagents. This is what `arsenal` calls by default and what you fire on
every new surface to raise wiki coverage cheaply. Stop here unless the surface is worth deep prep.

## Mode: deep (opt-in - "deep"/"full arsenal", or a whole service/target worth prepping)

Dispatch FOUR parallel subagents in a SINGLE message (Agent tool), one per area, with
`model: haiku` - each only reads its area and distils a card, which a lightweight model does well
at a fraction of the cost (a full-model fan-out measured ~170k tokens; haiku cuts that hard). Each
is told to search only its area, read the top 2-3 matching pages, and return a compact ready-to-use
card for its area ONLY (nothing else), citing the page paths it used:

| Agent | Searches | Returns |
|---|---|---|
| tools | `wiki/tools/` | the automated tool(s) to run + the exact command line |
| payloads | `wiki/payloads/` | ready-to-send payloads for the vuln-class |
| techniques | `wiki/techniques/` | the attack steps / chain |
| cheatsheets | `wiki/cheatsheets/` | quick copy-paste commands |

Each agent scopes its search to its area: pass a path filter to `qmd`, or query the whole index
and keep only `wiki/<area>/` hits, then read those pages. The pages an agent reads stay in that
agent's context and are discarded; you ingest only its card.

Merge the four returned cards into one arsenal card, four labelled sections plus a final
`Sources:` line listing every page used.

### Persist the deep card

Write the merged card to `targets/<active-eng>/arsenal/<slug>.md` (create the dir on demand) with
frontmatter `surface:` and `generated:`. That is the cache step 0 reads next time.

## Guardrails (token control)

- Default is quick (~1-2k tokens). Only go deep on request or for a real service/target.
- Deep is bounded: exactly 4 agents on `model: haiku`, each capped to the top 2-3 pages. The cost
  is isolated to the subagents; your main context only gains the merged card.
- The cache prevents re-spend on the same surface.

## Hand off

The full class-specific methodology lives in the matching `hunt-*` skill. After the arsenal card,
hand off to it (e.g. `Skill(hunt-ssrf)`) for the actual exploitation loop.
