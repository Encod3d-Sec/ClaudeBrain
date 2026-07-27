---
name: obsidian:read-vault
description: Read any file from the ClaudeBrain Obsidian vault by relative path. Resolves vault root automatically for the current machine.
type: tool
---

Read a vault file by its path relative to the vault root.

## Usage

```bash
VAULT="$(bash "$(dirname "$0")/../../setup/vault-path.sh" 2>/dev/null || bash ~/..claude/skills/obsidian/_vault-path.sh)"
cat "$VAULT/<relative-path>"
```

## How to use this skill

When you need to read a vault file, resolve the vault root first, then read:

```bash
VAULT=$(bash ~/.claude/skills/obsidian/_vault-root.sh)
cat "$VAULT/wiki/index.md"
```

Or use the helper directly in any Bash tool call:

```bash
VAULT=$(bash ~/.claude/skills/obsidian/_vault-root.sh)
cat "$VAULT/<relative-path>"
```

## Preference order

1. Use this skill (bash + cat via WSL path) for all vault file reads.
2. If a machine has the Obsidian Local REST API available, `mcp__obsidian-vault__*` is an alternative.
3. Never construct vault paths manually - always go through `vault-path.sh`

## Examples

```bash
# Read session startup files
VAULT=$(bash ~/.claude/skills/obsidian/_vault-root.sh)
cat "$VAULT/wiki/hot.md"
cat "$VAULT/wiki/ingested.md"
cat "$VAULT/wiki/index.md"
cat "$VAULT/raw/manifest.md"

# Read a specific technique page
cat "$VAULT/wiki/techniques/sql-injection.md"

# List a directory
ls "$VAULT/wiki/techniques/"
```
