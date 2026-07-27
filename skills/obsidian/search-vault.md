---
name: obsidian:search-vault
description: Search the ClaudeBrain vault. Uses qmd (semantic + keyword) when available; falls back to grep. Never read index.md manually to find pages - always search first.
type: tool
---

## Search priority

1. **Semantic / concept search** - `qmd query "<question>"` - use for "how does X work", "techniques related to Y", conceptual lookups
2. **Keyword / exact search** - `qmd search "<term>"` - use for CVE numbers, tool names, exact flags, specific strings
3. **Grep fallback** - only if qmd is unavailable

## Using qmd (preferred)

```bash
# Semantic search
qmd query "how does SQL injection work"

# Keyword search
qmd search "CVE-2021-44228"
qmd search "ffuf -w"

# If qmd MCP is registered, prefer MCP tools:
# mcp__wiki-search__qmd_query  -- semantic
# mcp__wiki-search__qmd_search -- keyword
```

## Grep fallback

```bash
VAULT=$(bash ~/.claude/skills/obsidian/_vault-root.sh)
grep -r "<term>" "$VAULT/wiki/" --include="*.md" -l
grep -r "<term>" "$VAULT/wiki/" --include="*.md" -n
```

## Rules

- Always search before reading files to find relevant pages
- Never read `wiki/index.md` manually to locate content - use search
- If qmd MCP server is unavailable, use `Bash(qmd query ...)` directly
- If qmd binary is missing, use grep fallback
