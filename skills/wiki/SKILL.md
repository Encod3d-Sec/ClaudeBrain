---
name: wiki
description: Search, query, and maintain the qmd-indexed wiki - semantic search, keyword search, re-index after adding pages, check index status.
type: cli
---

# Wiki Search and Maintenance

qmd is a CLI + MCP server that provides semantic and keyword search over `wiki/`. The MCP server (`wiki-search`) exposes two tools consumed by Claude Code directly. The CLI is used for maintenance (re-index, status).

All paths are relative to the vault root (`$QMD_VAULT`).

---

## Prerequisites

`QMD_VAULT` must point to your vault root (no trailing slash). Export it in your shell profile:

```bash
export QMD_VAULT="/path/to/your/ObsidianVaults/ClaudeBrain"
```

If a new session does not inherit it, prefix commands with `QMD_VAULT=... qmd ...` or source your profile. `qmd` is installed as a bun global (`bun install -g @qmd/cli`); if the `qmd` command is not found, ensure `~/.bun/bin` is on `PATH`.

---

## Searching via MCP (preferred in-session path)

When the `wiki-search` MCP is active, prefer these tools over the CLI - they avoid the 3-4 second model load on every invocation:

| Tool | Purpose |
|---|---|
| `mcp__wiki-search__qmd_query` | Semantic (vector) search - use for concepts, techniques, intent |
| `mcp__wiki-search__qmd_search` | Keyword (substring) search - use for exact strings, tool names, CVE IDs |

CLAUDE.md rule: **never read `wiki/index.md` to find pages - always search first.**

---

## Searching via CLI

Use when MCP is unavailable or for one-off maintenance.

**Semantic query (5 results, default):**

```bash
qmd query "CDN bypass origin IP"
```

**Semantic query (custom result count):**

```bash
qmd query -n 10 "JWT empty secret"
```

**Keyword search:**

```bash
qmd keyword "pnpm"
```

Output format: `[score] path/relative/to/wiki/` followed by a chunk of the matching content.

---

## Maintenance

**Re-index after adding or editing pages** (run once after a bulk write, not per file):

```bash
qmd update
```

Expected output: `Indexing wiki... Done. N chunks indexed.`

The CUDA warning about an old driver is harmless - the model runs on CPU.

**Check index size:**

```bash
qmd status
```

Output: `Collection: wiki  Chunks: N`

### Integrity and catalog upkeep

These run automatically at SessionStart (via `engagement-init.py`); run them by hand after a bulk edit, rename, or before sharing:

```bash
python3 scripts/gen_index.py     # rebuild wiki/index.md catalog (idempotent; --check tests only)
python3 scripts/lint-wiki.py     # broken links, dead script refs, frontmatter gaps, stale index, lean areas
python3 scripts/build_moc.py     # rebuild graph hubs so every page stays reachable
```

`lint-wiki.py` exits non-zero on hard problems - use it as a pre-share / pre-commit gate. `index.md` and the `*-moc.md` hubs are generated; never hand-edit them.

---

## Promote candidates

Generic, reusable knowledge found live during an engagement is staged to a review
queue under `targets/<eng>/wiki-candidates/` (gitignored) the moment it is confirmed,
not at engagement end. It reaches `wiki/` only through the leak-gated promoter.

```bash
python3 scripts/wiki-promote.py --list             # pending candidates (slug, kind, page)
python3 scripts/wiki-promote.py --review <slug>    # read one candidate in full
python3 scripts/wiki-promote.py --promote <slug>   # or: --promote all
```

`--promote` runs `scripts/check-leaks.sh --file` on the candidate BODY. If a client
marker is present it refuses and writes nothing; if clean it merges into
`wiki/<target_page>` (dedup by slug), sets `status: promoted`, archives the file to
`wiki-candidates/_promoted/`, and re-indexes (`gen_index.py` + `qmd update`). Stage a
new candidate with `scripts/wiki-stage.py --kind <default-cred|api-pattern|technique>
--slug <slug>`. This is the only path that writes engagement-derived knowledge into
`wiki/`, so the client-data boundary is enforced by code, not prose.

---

## Broken install recovery

If `qmd` fails:

1. Confirm the `qmd` binary is on `PATH` (`command -v qmd`); it installs to `~/.bun/bin/qmd` via `bun install -g @qmd/cli`.
2. Check `QMD_VAULT` is set and points to the current vault path (no trailing slash, no spaces encoded).
3. The index lives under `~/.qmd/` - if the collection is missing, run `qmd update` to rebuild from scratch.

---

## Files

| Path | Purpose |
|---|---|
| `~/.bun/bin/qmd` | qmd CLI + MCP binary (bun global) |
| `~/.qmd/` | local search index |
| `$QMD_VAULT/wiki/` | the markdown corpus that gets indexed |
