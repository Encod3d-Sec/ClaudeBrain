# Skills & MCP Setup

Operational reference for managing plugins, MCP servers, and hooks in this vault.
Add new entries here whenever a plugin is added, removed, or breaks.

---

## Active MCP Servers

### wiki-search (qmd)

Semantic and keyword search across `wiki/`. Required for all vault search operations.

```json
"wiki-search": {
  "type": "stdio",
  "command": "python3",
  "args": ["-m", "qmd.mcp_server"],
  "env": { "QMD_VAULT": "/mnt/c/Users/{user}/Documents/ObsidianVaults/ClaudeBrain" }
}
```

Replace `{user}` with your Windows username (the WSL path is
`/mnt/c/Users/<you>/Documents/ObsidianVaults/ClaudeBrain`). If you keep a
per-machine table, it lives in the git-ignored `CLAUDE.local.md`.

Config location: `~/.claude.json` -> `mcpServers`
Rebuild index: `qmd update` (run from vault root after bulk wiki changes)

### obsidian-vault (removed)

Previously used `mcp-obsidian` (Obsidian Local REST API). Removed because:
- Requires Obsidian app to be running on Windows - breaks if closed
- Not needed: Claude Code's `Read` tool accesses vault files directly via WSL path

**Replacement:** `Read /mnt/c/Users/{user}/Documents/ObsidianVaults/ClaudeBrain/<relative-path>` (see machine usernames above)

---

## Plugin Troubleshooting

### context7 - stale lock files crash the plugin

**Symptom:** context7 fails to start or crashes sessions on startup.

**Cause:** context7 is an external plugin (`npx -y @upstash/context7-mcp`) with no version
in its manifest, so all sessions share one `unknown/` cache directory. When a session exits
uncleanly (WSL restart, force-kill), its PID lock file is never removed. On next startup
Claude Code sees orphaned locks and fails to connect.

**Manual fix:**
```bash
rm -f ~/.claude/plugins/cache/claude-plugins-official/context7/unknown/.in_use/*
```
Safe to run any time Claude Code is not actively running.

**Automatic fix:** SessionStart hook (see below).

---

## Hooks

### SessionStart - context7 lock cleanup

Stale context7 PID lock files can crash the plugin on startup. The registered
`session-start.sh` SessionStart hook clears them (and loads `session/hot.md`);
`bash setup/install-hooks.sh` registers it, so no manual `settings.json` edit is needed.
The cleanup logic:

```bash
LOCK_DIR="$HOME/.claude/plugins/cache/claude-plugins-official/context7/unknown/.in_use"
[ -d "$LOCK_DIR" ] && for f in "$LOCK_DIR"/*; do
  [ -f "$f" ] || continue
  pid=$(python3 -c "import json; print(json.load(open('$f')).get('pid',''))" 2>/dev/null)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || rm -f "$f"
done
```

---

## Disabled Plugins

| Plugin | Reason |
|--------|--------|
| obsidian-vault MCP | Requires Obsidian running; replaced by direct Read tool |
| context7 (was crashing) | Fixed via lock cleanup above; now re-enabled |
